#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

char LICENSE[] SEC("license") = "GPL";

// Forward rule structure
struct forward_rule {
    __u32 target_ip;      // Target IP in network byte order
    __u16 target_port;    // Target port in network byte order
    __u32 allowed_ip;     // Allowed source IP in network byte order (for CIDR matching)
    __u32 allowed_mask;   // CIDR mask in network byte order (e.g., 0xFFFFFF00 for /24)
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);  // listen_port in network byte order
    __type(value, struct forward_rule);
} forward_rules SEC(".maps");

// Reverse mapping for return traffic
struct reverse_key {
    __u32 target_ip;
    __u32 client_ip;
    __u16 target_port;
    __u16 client_port;
} __attribute__((packed));

struct reverse_value {
    __u32 local_ip;
    __u16 local_port;
    __u32 client_ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct reverse_key);
    __type(value, struct reverse_value);
} reverse_rules SEC(".maps");

// Event types
#define EVENT_FORWARD_ATTEMPT 1
#define EVENT_FORWARD_SUCCESS 2
#define EVENT_XDP_ENTRY 3
#define EVENT_DEBUG 4
#define EVENT_TCP_TUPLE 5
#define EVENT_REVERSE_SUCCESS 6

// Event structure for logging
struct forward_event {
    __u8 type;
    union {
        struct {
            __u32 src_ip;
            __u32 orig_dst_ip;
            __u16 orig_dst_port;
            __u32 new_dst_ip;
            __u16 new_dst_port;
        };
        struct {
            __u32 tcp_src_ip;
            __u32 tcp_dst_ip;
            __u16 tcp_src_port;
            __u16 tcp_dst_port;
            __u8 tcp_protocol;
        };
        char msg[64];
    };
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} forward_events SEC(".maps");

// Helper: send event
static __always_inline void send_forward_event(__u8 event_type, __u32 src_ip,
                                             __u32 orig_dst_ip, __u16 orig_dst_port,
                                             __u32 new_dst_ip, __u16 new_dst_port) {
    struct forward_event *e = bpf_ringbuf_reserve(&forward_events, sizeof(*e), 0);
    if (!e) return;

    __builtin_memset(e, 0, sizeof(*e));
    e->type = event_type;
    e->src_ip = src_ip;
    e->orig_dst_ip = orig_dst_ip;
    e->orig_dst_port = orig_dst_port;
    e->new_dst_ip = new_dst_ip;
    e->new_dst_port = new_dst_port;

    bpf_ringbuf_submit(e, 0);
}

// Helper: send debug log (patterned after agent.bpf.c)
static __always_inline void send_debug_log(const char *prefix, const char *msg) {
    struct forward_event *e = bpf_ringbuf_reserve(&forward_events, sizeof(*e), 0);
    if (!e) return;

    __builtin_memset(e, 0, sizeof(*e));
    e->type = EVENT_DEBUG;
    // Using memcpy instead of snprintf to avoid relocation issues if helper is missing
    __builtin_memcpy(e->msg, msg, 32); 
    bpf_ringbuf_submit(e, 0);
}

// Checksum helpers
static __always_inline __u16 csum_fold_helper(__u32 csum) {
    for (int i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline void ipv4_csum_inline(struct iphdr *iph) {
    __u16 *next_iph_u16 = (__u16 *)iph;
    __u32 csum = 0;
    iph->check = 0;
#pragma unroll
    for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
        csum += *next_iph_u16++;
    }
    iph->check = csum_fold_helper(csum);
}

// Helper for incremental checksum update
// See RFC 1624
static __always_inline void csum_replace2(__u16 *csum, __u16 old_val, __u16 new_val) {
    __u32 new_csum = *csum;
    new_csum = ~new_csum & 0xFFFF;
    new_csum += ~old_val & 0xFFFF;
    new_csum += new_val;
    new_csum = (new_csum >> 16) + (new_csum & 0xFFFF);
    new_csum += (new_csum >> 16);
    *csum = ~new_csum & 0xFFFF;
}

static __always_inline void csum_replace4(__u16 *csum, __u32 old_val, __u32 new_val) {
    csum_replace2(csum, old_val & 0xFFFF, new_val & 0xFFFF);
    csum_replace2(csum, old_val >> 16, new_val >> 16);
}

// Main sock_addr hook
SEC("cgroup/connect4")
int forward_connect(struct bpf_sock_addr *ctx) {
    // Only handle IPv4 TCP/UDP connections
    if (ctx->family != AF_INET) {
        send_debug_log("CGROUP", "not IPv4, allow");
        return 1; // Allow
    }

    __u16 dst_port = ctx->user_port;  // Network byte order
    __u32 dst_ip = ctx->user_ip4;     // Network byte order

    // Check if this port has a forward rule
    struct forward_rule *rule = bpf_map_lookup_elem(&forward_rules, &dst_port);
    if (!rule) {
        return 1; // No rule, allow original connection
    }

    // Send event for forward attempt
    send_forward_event(EVENT_FORWARD_ATTEMPT, 0, dst_ip, dst_port, rule->target_ip, rule->target_port);

    // Redirect: change destination IP and port
    ctx->user_ip4 = rule->target_ip;
    ctx->user_port = rule->target_port;

    send_debug_log("CGROUP", "REDIRECT successful");

    // Send success event
    send_forward_event(EVENT_FORWARD_SUCCESS, 0, dst_ip, dst_port, rule->target_ip, rule->target_port);

    return 1; // Allow modified connection
}

// XDP hook for remote/ingress redirection
SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)eth + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u16 dst_port = 0;
    
    // Boundary check for variable length IP header
    __u8 ihl = ip->ihl;
    if (ihl < 5)
        return XDP_PASS;
    void *l4_hdr = (void *)ip + (ihl * 4);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_hdr;
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return XDP_PASS;
        dst_port = tcp->dest;
#if 0
        __u16 src_port = tcp->source;
        // Send TCP tuple event to userspace
        struct forward_event *tcp_event = bpf_ringbuf_reserve(&forward_events, sizeof(*tcp_event), 0);
        if (tcp_event) {
            tcp_event->type = EVENT_TCP_TUPLE;
            tcp_event->tcp_src_ip = src_ip;
            tcp_event->tcp_dst_ip = dst_ip;
            tcp_event->tcp_src_port = src_port;
            tcp_event->tcp_dst_port = dst_port;
            tcp_event->tcp_protocol = ip->protocol;
            bpf_ringbuf_submit(tcp_event, 0);
        }
#endif
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4_hdr;
        if ((void *)udp + sizeof(*udp) > data_end)
            return XDP_PASS;
        dst_port = udp->dest;
    } else {
        return XDP_PASS;
    }

    struct forward_rule *rule = bpf_map_lookup_elem(&forward_rules, &dst_port);
    if (!rule) {
        // Check if this is return traffic from a target to a client
        // Re-check l4_hdr for verifier in this branch
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = l4_hdr;
            if ((void *)tcp + sizeof(*tcp) > data_end)
                return XDP_PASS;
            
            struct reverse_key r_key;
            __builtin_memset(&r_key, 0, sizeof(r_key));
            r_key.target_ip = src_ip;
            r_key.target_port = tcp->source;
            r_key.client_ip = dst_ip;
            r_key.client_port = tcp->dest;

            struct reverse_value *r_val = bpf_map_lookup_elem(&reverse_rules, &r_key);
            if (r_val) {
                 // 1. Translate Source: target_ip:target_port -> local_ip:local_port
                 csum_replace4(&tcp->check, src_ip, r_val->local_ip);
                 csum_replace2(&tcp->check, r_key.target_port, r_val->local_port);
                 tcp->source = r_val->local_port;

                 csum_replace4(&ip->check, src_ip, r_val->local_ip);
                 ip->saddr = r_val->local_ip;

                 // 2. Translate Destination: local_ip -> client_ip
                 csum_replace4(&tcp->check, dst_ip, r_val->client_ip);
                 // tcp->dest is already correct (dst_port == client_port)
                 
                 csum_replace4(&ip->check, dst_ip, r_val->client_ip);
                 ip->daddr = r_val->client_ip;

                 // Send reverse success event: SRC, OLD_DST, OLD_DST_P, NEW_DST, NEW_DST_P
                 send_forward_event(EVENT_REVERSE_SUCCESS, src_ip, dst_ip, dst_port, r_val->client_ip, r_val->local_port);
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = l4_hdr;
            if ((void *)udp + sizeof(*udp) > data_end)
                return XDP_PASS;

            struct reverse_key r_key;
            __builtin_memset(&r_key, 0, sizeof(r_key));
            r_key.target_ip = src_ip;
            r_key.target_port = udp->source;
            r_key.client_ip = dst_ip;
            r_key.client_port = udp->dest;

            struct reverse_value *r_val = bpf_map_lookup_elem(&reverse_rules, &r_key);
            if (r_val) {
                 // 1. Translate Source
                 if (udp->check) {
                     csum_replace4(&udp->check, src_ip, r_val->local_ip);
                     csum_replace2(&udp->check, r_key.target_port, r_val->local_port);
                 }
                 udp->source = r_val->local_port;

                 csum_replace4(&ip->check, src_ip, r_val->local_ip);
                 ip->saddr = r_val->local_ip;

                 // 2. Translate Destination
                 if (udp->check) {
                     csum_replace4(&udp->check, dst_ip, r_val->client_ip);
                 }
                 csum_replace4(&ip->check, dst_ip, r_val->client_ip);
                 ip->daddr = r_val->client_ip;

                 // Send reverse success event: SRC, OLD_DST, OLD_DST_P, NEW_DST, NEW_DST_P
                 send_forward_event(EVENT_REVERSE_SUCCESS, src_ip, dst_ip, dst_port, r_val->client_ip, r_val->local_port);
            }
        }
        return XDP_PASS;
    }

    // Store reverse mapping for return traffic
    struct reverse_key r_key;
    __builtin_memset(&r_key, 0, sizeof(r_key));
    r_key.target_ip = rule->target_ip;
    r_key.target_port = rule->target_port;
    r_key.client_ip = dst_ip;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_hdr;
        if ((void *)tcp + sizeof(*tcp) <= data_end)
            r_key.client_port = tcp->source;
    } else {
        struct udphdr *udp = l4_hdr;
        if ((void *)udp + sizeof(*udp) <= data_end)
            r_key.client_port = udp->source;
    }
    
    struct reverse_value r_val;
    __builtin_memset(&r_val, 0, sizeof(r_val));
    r_val.local_ip = dst_ip;
    r_val.local_port = dst_port;
    r_val.client_ip = src_ip;
    
    bpf_map_update_elem(&reverse_rules, &r_key, &r_val, BPF_ANY);

    // Redirect + SNAT
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_hdr;
        // Re-check for verifier
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return XDP_PASS;
        
        // DNAT: target_ip:target_port
        csum_replace4(&tcp->check, dst_ip, rule->target_ip);
        csum_replace2(&tcp->check, dst_port, rule->target_port);
        tcp->dest = rule->target_port;
        
        // SNAT: source = local_ip (dst_ip)
        csum_replace4(&tcp->check, src_ip, dst_ip);
        // source port remains same
    } else {
        struct udphdr *udp = l4_hdr;
        // Re-check for verifier
        if ((void *)udp + sizeof(*udp) > data_end)
            return XDP_PASS;
        
        // DNAT
        if (udp->check) {
            csum_replace4(&udp->check, dst_ip, rule->target_ip);
            csum_replace2(&udp->check, dst_port, rule->target_port);
        }
        udp->dest = rule->target_port;

        // SNAT
        if (udp->check) {
            csum_replace4(&udp->check, src_ip, dst_ip);
        }
    }
    
    // IP header updates
    csum_replace4(&ip->check, dst_ip, rule->target_ip);
    ip->daddr = rule->target_ip;
    
    csum_replace4(&ip->check, src_ip, dst_ip);
    ip->saddr = dst_ip;

    send_debug_log("XDP", "Redirecting packet");

    // Send event
    send_forward_event(EVENT_FORWARD_SUCCESS, src_ip, dst_ip, dst_port, rule->target_ip, rule->target_port);

    return XDP_PASS;
}
