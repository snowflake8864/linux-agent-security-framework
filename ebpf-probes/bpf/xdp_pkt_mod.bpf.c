#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// Fix missing constants
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
char LICENSE[] SEC("license") = "GPL";

// Event types
#define EVENT_NET 3
#define EVENT_DEBUG 4

// Event structure for ring buffer
struct pkt_event {
    __u8 type;
    __u8 protocol;
    __u8 tcp_flags_set;
    __u8 padding1;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

// Maps for XDP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
} block_rules SEC(".maps");

struct pkt_mod_key {
    __u8 protocol;    // 6=TCP, 17=UDP, 1=ICMP, 0=any
    __u8 direction;   // 0=any, 1=ingress, 2=egress
    __u8 padding[2];
    __u32 dst_ip;     // Network byte order, 0 = any
    __u16 src_port;   // Network byte order, 0 = any
    __u16 dst_port;   // Network byte order, 0 = any
};

struct pkt_mod_value {
    // TCP flags modification
    __u8 tcp_flags_enable;      // 1 = modify TCP flags
    __u8 tcp_set_ecn_echo;      // 1 = set ECN-Echo flag
    __u8 tcp_set_cwr;           // 1 = set CWR flag
    __u8 tcp_set_reserved;      // 1 = set all 4 reserved bits
    __u8 tcp_flags_mask;        // Mask for standard TCP flags
    __u8 tcp_flags_value;       // Value for standard TCP flags
    __u8 reserved_bits_mask;    // Mask for 4 reserved bits
    __u8 reserved_bits_value;   // Value for 4 reserved bits

    // Port modification
    __u8 port_mod_enable;       // 1 = modify ports
    __u16 new_src_port;         // Network byte order, 0 = no change
    __u16 new_dst_port;         // Network byte order, 0 = no change

    // IP modification
    __u8 ip_mod_enable;         // 1 = modify IPs
    __u32 new_src_ip;           // Network byte order, 0 = no change
    __u32 new_dst_ip;           // Network byte order, 0 = no change
    __u32 allowed_ip;           // Network byte order
    __u32 allowed_mask;         // Network byte order

    __u8 padding[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct pkt_mod_key);
    __type(value, struct pkt_mod_value);
} pkt_mod_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} pkt_events SEC(".maps");

// Helper: send event
static __always_inline void send_event(struct pkt_event *e) {
    bpf_ringbuf_submit(e, 0);
}

// Helper: find rule with wildcards
static __always_inline struct pkt_mod_value *find_rule(__u8 protocol, __u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port) {
    __u8 direction = 1; // XDP is always Ingress
    struct pkt_mod_key key = {
        .protocol = protocol,
        .direction = direction,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
    };

    // 1. Exact match (proto + direction + ip + ports)
    struct pkt_mod_value *rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    // Try direction Any
    key.direction = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;
    key.direction = direction;

    // 2. Try proto + ip + dst_port (wildcard src_port)
    key.src_port = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    key.direction = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;
    key.direction = direction;

    // 3. Try proto + dst_port only (wildcard IP and src_port)
    key.dst_ip = 0;
    key.src_port = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    key.direction = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;
    key.direction = direction;

    // 4. Try proto + dst_ip only
    key.dst_ip = dst_ip;
    key.src_port = 0;
    key.dst_port = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    key.direction = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;
    key.direction = direction;

    // 5. Try proto only
    key.dst_ip = 0;
    key.src_port = 0;
    key.dst_port = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    key.direction = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    return rule;
}

// XDP program for packet modification
SEC("xdp")
int xdp_packet_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_proto = eth->h_proto;
    if (eth_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)eth + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u8 protocol = ip->protocol;
    __u32 src_ip = bpf_ntohl(ip->saddr);
    __u32 dst_ip = bpf_ntohl(ip->daddr);

    if (protocol != 6 && protocol != 17)
        return XDP_PASS;

    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    __u16 src_port = 0, dst_port = 0;

    if (protocol == 6) {
        tcp = (void *)ip + sizeof(*ip);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        src_port = tcp->source;
        dst_port = tcp->dest;
    } else {
        udp = (void *)ip + sizeof(*ip);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        src_port = udp->source;
        dst_port = udp->dest;
    }

    bpf_printk("[XDP] PKT: proto=%u src=%pI4:%u", protocol, &ip->saddr, bpf_ntohs(src_port));
    bpf_printk("[XDP] PKT: dst=%pI4:%u", &ip->daddr, bpf_ntohs(dst_port));

    // Check block rules first
    __u16 block_key = bpf_ntohs(dst_port);
    __u8 *blocked = bpf_map_lookup_elem(&block_rules, &block_key);
    if (blocked && *blocked) {
        bpf_printk("[XDP] 🚫 Port %u blocked by rule", block_key);
        // Send block event
        struct pkt_event *e = bpf_ringbuf_reserve(&pkt_events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_NET;
            e->protocol = protocol;
            e->src_ip = src_ip;
            e->dst_ip = dst_ip;
            e->src_port = src_port;
            e->dst_port = dst_port;
            e->tcp_flags_set = 0x80; // Block flag
            send_event(e);
        }
        return XDP_DROP;
    }

    // Find rule (exact or wildcard)
    struct pkt_mod_value *rule = find_rule(protocol, src_ip, dst_ip, src_port, dst_port);
    if (!rule) {
        // Send event for all packets
        struct pkt_event *e = bpf_ringbuf_reserve(&pkt_events, sizeof(*e), 0);
            if (e) {
                e->type = EVENT_NET;
                e->protocol = protocol;
                e->src_ip = src_ip;
                e->dst_ip = dst_ip;
                e->src_port = src_port;
                e->dst_port = dst_port;
                e->tcp_flags_set = 0x00; // PASSED
                send_event(e);
            }
            return XDP_PASS;
        }

    // Apply modifications from rule
    if (protocol == 6 && rule->tcp_flags_enable) {
        __u8 *flags_byte = (__u8 *)tcp + 13;
        __u8 *reserved_byte = (__u8 *)tcp + 12;

        if (rule->tcp_set_reserved) {
            *reserved_byte = (*reserved_byte & 0xF0) | 0x0F;
        } else if (rule->reserved_bits_mask) {
            *reserved_byte = (*reserved_byte & (~rule->reserved_bits_mask | 0xF0)) |
                             (rule->reserved_bits_value & rule->reserved_bits_mask & 0x0F);
        }

        if (rule->tcp_set_cwr) {
            *flags_byte |= (1 << 7);
        }
        if (rule->tcp_set_ecn_echo) {
            *flags_byte |= (1 << 6);
        }
        
        // Apply mask/value if provided for flags
        if (rule->tcp_flags_mask) {
            *flags_byte = (*flags_byte & ~rule->tcp_flags_mask) |
                         (rule->tcp_flags_value & rule->tcp_flags_mask);
        }
    }

    // Port modification
    if (rule->port_mod_enable) {
        if (protocol == 6) {
            if (rule->new_dst_port && tcp->dest != rule->new_dst_port) {
                tcp->dest = rule->new_dst_port;
            }
        } else {
            if (rule->new_dst_port && udp->dest != rule->new_dst_port) {
                udp->dest = rule->new_dst_port;
            }
        }
    }

    // IP modification
    if (rule->ip_mod_enable) {
        if (rule->new_dst_ip && ip->daddr != rule->new_dst_ip) {
            ip->daddr = rule->new_dst_ip;
        }
    }

    // Send modification event
    struct pkt_event *e = bpf_ringbuf_reserve(&pkt_events, sizeof(*e), 0);
    if (e) {
        e->type = EVENT_NET;
        e->protocol = protocol;
        e->src_ip = src_ip;
        e->dst_ip = dst_ip;
        e->src_port = src_port;
        e->dst_port = dst_port;
        e->tcp_flags_set = 0x40; // Modified flag
        send_event(e);
    }

    return XDP_PASS;
}