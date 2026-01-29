// eBPF TC Egress: Network Packet Modification
// This is a standalone TC program for packet modification

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// Fix missing constants
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif
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
#define EVENT_DEBUG 4  // New debug event type

// Event structure for ring buffer (simplified for TC context)
struct pkt_event {
    __u8 type;           // EVENT_NET = 3
    __u8 protocol;
    __u8 tcp_flags_set;  // Which TCP flags were set (bitmask)
    __u8 padding1;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

// Enhanced debug event structure (sent to userspace)
struct debug_event {
    __u8 type;              // EVENT_DEBUG = 4
    __u8 event_subtype;     // 0=pkt_info, 1=rule_match, 2=modification
    __u8 protocol;
    __u8 rule_matched;      // 0=no, 1=yes
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 matched_dst_port; // Port from matched rule
    __u8 tcp_flags_enable;
    __u8 reserved_bits_mask;
    __u8 reserved_bits_value;
    __u8 padding[1];
};

// Packet modification rule key: match by protocol + direction + dst_ip + dst_port
struct pkt_mod_key {
    __u8 protocol;    // 6=TCP, 17=UDP, 1=ICMP, 0=any
    __u8 direction;   // 0=any, 1=ingress, 2=egress
    __u8 padding[2];
    __u32 dst_ip;     // Network byte order, 0 = any
    __u16 src_port;   // Network byte order, 0 = any
    __u16 dst_port;   // Network byte order, 0 = any
};

// Packet modification rule value
struct pkt_mod_value {
    // TCP flags modification
    __u8 tcp_flags_enable;      // 1 = modify TCP flags
    __u8 tcp_set_ecn_echo;      // 1 = set ECN-Echo flag (bit 6 of flags byte)
    __u8 tcp_set_cwr;           // 1 = set CWR flag (bit 7 of flags byte)
    __u8 tcp_set_reserved;      // 1 = set all 4 reserved bits (deprecated)
    __u8 tcp_flags_mask;        // Mask for standard TCP flags (byte 13)
    __u8 tcp_flags_value;       // Value for standard TCP flags (byte 13)
    __u8 reserved_bits_mask;    // Mask for 4 reserved bits in byte 12 (lower 4 bits)
    __u8 reserved_bits_value;   // Value for 4 reserved bits in byte 12

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

// Block rules: key = dst_port (u16), value = 1 if blocked
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
} block_rules SEC(".maps");

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

// === Checksum helpers ===
static __always_inline __u16 csum_fold(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline __u32 csum_unfold(__u16 csum) {
    return (__u32)csum;
}

static __always_inline __u16 csum_update(__u16 old_csum, __u16 old_val, __u16 new_val) {
    __u32 csum = csum_unfold(old_csum);
    csum += csum_unfold(~old_val);
    csum += csum_unfold(new_val);
    return csum_fold(csum);
}

static __always_inline __u16 csum_update32(__u16 old_csum, __u32 old_val, __u32 new_val) {
    __u32 csum = csum_unfold(old_csum);
    csum += csum_unfold(~(__u16)(old_val & 0xffff));
    csum += csum_unfold(~(__u16)(old_val >> 16));
    csum += csum_unfold((__u16)(new_val & 0xffff));
    csum += csum_unfold((__u16)(new_val >> 16));
    return csum_fold(csum);
}

// === Event helper ===
static __always_inline void send_pkt_event(struct __sk_buff *skb,
                                           __u8 protocol,
                                           __u32 src_ip, __u32 dst_ip,
                                           __u16 src_port, __u16 dst_port,
                                           __u8 tcp_flags_set) {
    struct pkt_event *e = bpf_ringbuf_reserve(&pkt_events, sizeof(*e), 0);
    if (!e)
        return;

    e->type = EVENT_NET;
    e->protocol = protocol;
    e->tcp_flags_set = tcp_flags_set;
    e->padding1 = 0;
    e->src_ip = src_ip;
    e->dst_ip = dst_ip;
    e->src_port = src_port;
    e->dst_port = dst_port;

    bpf_ringbuf_submit(e, 0);
}

// Helper: send event
static __always_inline void send_event(struct pkt_event *e) {
    bpf_ringbuf_submit(e, 0);
}

// === Debug event helper (sends to userspace instead of kernel log) ===
static __always_inline void send_debug_event(__u8 subtype,
                                             __u8 protocol,
                                             __u32 src_ip, __u32 dst_ip,
                                             __u16 src_port, __u16 dst_port,
                                             __u8 rule_matched,
                                             __u16 matched_dst_port,
                                             __u8 tcp_flags_enable,
                                             __u8 reserved_bits_mask,
                                             __u8 reserved_bits_value) {
    struct debug_event *e = bpf_ringbuf_reserve(&pkt_events, sizeof(*e), 0);
    if (!e)
        return;

    e->type = EVENT_DEBUG;
    e->event_subtype = subtype;
    e->protocol = protocol;
    e->rule_matched = rule_matched;
    e->src_ip = src_ip;
    e->dst_ip = dst_ip;
    e->src_port = src_port;
    e->dst_port = dst_port;
    e->matched_dst_port = matched_dst_port;
    e->tcp_flags_enable = tcp_flags_enable;
    e->reserved_bits_mask = reserved_bits_mask;
    e->reserved_bits_value = reserved_bits_value;
    e->padding[0] = 0;

    bpf_ringbuf_submit(e, 0);
}

// Helper: find rule with direction and wildcards
static __always_inline struct pkt_mod_value *find_rule(__u8 protocol, __u8 direction, __u32 dst_ip, __u16 src_port, __u16 dst_port) {
    struct pkt_mod_key key = {
        .protocol = protocol,
        .direction = direction,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
    };

    // 1. Try exact match (proto + direction + ip + src_port + dst_port)
    struct pkt_mod_value *rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    // Try direction Any
    if (direction != 0) {
        key.direction = 0;
        rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
        if (rule) return rule;
        key.direction = direction;
    }

    // 2. Try proto + ip + dst_port (wildcard src_port)
    key.src_port = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    if (direction != 0) {
        key.direction = 0;
        rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
        if (rule) return rule;
        key.direction = direction;
    }

    // 3. Try proto + dst_port only (wildcard IP and src_port)
    key.dst_ip = 0;
    key.src_port = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    if (direction != 0) {
        key.direction = 0;
        rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
        if (rule) return rule;
        key.direction = direction;
    }

    // 4. Try proto + dst_ip only (wildcard ports)
    key.dst_ip = dst_ip;
    key.src_port = 0;
    key.dst_port = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    if (direction != 0) {
        key.direction = 0;
        rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
        if (rule) return rule;
        key.direction = direction;
    }

    // 5. Try proto only
    key.dst_ip = 0;
    key.src_port = 0;
    key.dst_port = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    if (direction != 0) {
        key.direction = 0;
        rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
        if (rule) return rule;
    }

    return NULL;
}

// === Main TC program core ===
static __always_inline int tc_pkt_modifier_common(struct __sk_buff *skb, __u8 direction)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u8 protocol = ip->protocol;
    __u32 src_ip = bpf_ntohl(ip->saddr);  // Host byte order
    __u32 dst_ip = bpf_ntohl(ip->daddr);  // Host byte order
    __u16 src_port = 0;
    __u16 dst_port = 0;
    void *l4 = (void *)ip + (ip->ihl * 4);

    // DEBUG: Print packet info
    bpf_printk("[TC] PKT: dir=%u proto=%u", direction, protocol);
    bpf_printk("[TC] PKT: src=%pI4 dst=%pI4", &src_ip, &dst_ip);

    // Declare variables before any labels (C89 requirement)
    int modified = 0;
    __u8 tcp_flags_set = 0;

    // Send packet info to userspace (debug event)
    send_debug_event(0, protocol, src_ip, dst_ip, src_port, dst_port, 0, 0, 0, 0, 0);

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        src_port = tcp->source;  // Network byte order (big-endian)
        dst_port = tcp->dest;    // Network byte order (big-endian)
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        src_port = udp->source;  // Network byte order (big-endian)
        dst_port = udp->dest;    // Network byte order (big-endian)
    }

    // Check block rules first
    __u16 block_key = bpf_ntohs(dst_port);
    __u8 *blocked = bpf_map_lookup_elem(&block_rules, &block_key);
    if (blocked && *blocked) {
        bpf_printk("[TC] 🚫 Port %u blocked by rule", block_key);
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
            bpf_ringbuf_submit(e, 0);
        }
        return TC_ACT_SHOT;
    }

    // Find rule (exact or wildcard)
    struct pkt_mod_value *rule = find_rule(protocol, direction, dst_ip, src_port, dst_port);
    
    if (!rule) {
        // No match found
        bpf_printk("[TC] ✗ No matching rule found");
        // Send no-match event to userspace
        send_debug_event(1, protocol, src_ip, dst_ip, src_port, dst_port, 0, 0, 0, 0, 0);

        // Send PASSED event
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
        return TC_ACT_OK;
    }

apply_rule:
    bpf_printk("[TC] Applying rule: tcp_flags_en=%u port_mod_en=%u ip_mod_en=%u",
               rule->tcp_flags_enable, rule->port_mod_enable, rule->ip_mod_enable);

    // === 1. TCP flags modification ===
    if (protocol == IPPROTO_TCP && rule->tcp_flags_enable) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;

        __u8 *flags_byte = (__u8 *)tcp + 13;
        __u8 old_flags = *flags_byte;
        __u8 new_flags = old_flags;

        if (rule->tcp_set_ecn_echo) {
            new_flags |= (1 << 6); // ECE bit (0x40)
            tcp_flags_set |= 0x01;
        }
        if (rule->tcp_set_cwr) {
            new_flags |= (1 << 7); // CWR bit (0x80)
            tcp_flags_set |= 0x02;
        }

        // Apply mask/value if provided
        if (rule->tcp_flags_mask) {
            new_flags = (new_flags & ~rule->tcp_flags_mask) |
                        (rule->tcp_flags_value & rule->tcp_flags_mask);
        }

        if (old_flags != new_flags) {
            tcp->check = csum_update(tcp->check, old_flags, new_flags);
            *flags_byte = new_flags;
            modified = 1;
            bpf_printk("[TC] TCP flags modified: 0x%02x -> 0x%02x", old_flags, new_flags);
        }

        // === Reserved bits (byte 12) - NOT in checksum ===
        // TCP byte 12 format: [Data Offset: 4 bits][Reserved: 4 bits]
        // Reserved 4 bits in byte 12 + ECE/CWR in byte 13 = 6 reserved bits total
        
        // Legacy: set all 4 bits
        if (rule->tcp_set_reserved) {
            __u8 *reserved_byte = (__u8 *)tcp + 12;
            __u8 old_res = *reserved_byte;
            __u8 new_res = (old_res & 0xF0) | 0x0F; // set lower 4 bits
            if (old_res != new_res) {
                *reserved_byte = new_res;
                modified = 1;
                tcp_flags_set |= 0x04;
                bpf_printk("[TC] Reserved bits (mask/val): 0x%02x -> 0x%02x, now %x", old_res, new_res, *reserved_byte);
            }
        }
        // New flexible approach: use mask + value for specific bit patterns
        else if (rule->reserved_bits_mask) {
            __u8 *reserved_byte = (__u8 *)tcp + 12;
            __u8 old_res = *reserved_byte;
            // Apply mask and value only to lower 4 bits (reserved bits)
            __u8 new_res = (old_res & (~rule->reserved_bits_mask | 0xF0)) |
                          (rule->reserved_bits_value & rule->reserved_bits_mask & 0x0F);
            if (old_res != new_res) {
                *reserved_byte = new_res;
                modified = 1;
                tcp_flags_set |= 0x04;
                bpf_printk("[TC] Reserved bits (mask/val): 0x%02x -> 0x%02x val=%u", old_res, new_res, rule->reserved_bits_value);
                bpf_printk("[TC]   mask=0x%02x val=0x%02x", rule->reserved_bits_mask, rule->reserved_bits_value);
            }
        }
    }

    // === 2. Port modification ===
    if (rule->port_mod_enable) {
        if (protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = l4;
            if ((void *)(tcp + 1) > data_end)
                return TC_ACT_OK;

            if (rule->new_src_port && tcp->source != rule->new_src_port) {
                tcp->check = csum_update(tcp->check, tcp->source, rule->new_src_port);
                tcp->source = rule->new_src_port;
                modified = 1;
            }
            if (rule->new_dst_port && tcp->dest != rule->new_dst_port) {
                tcp->check = csum_update(tcp->check, tcp->dest, rule->new_dst_port);
                tcp->dest = rule->new_dst_port;
                modified = 1;
            }
        } else if (protocol == IPPROTO_UDP) {
            struct udphdr *udp = l4;
            if ((void *)(udp + 1) > data_end)
                return TC_ACT_OK;

            if (rule->new_src_port && udp->source != rule->new_src_port) {
                if (udp->check)
                    udp->check = csum_update(udp->check, udp->source, rule->new_src_port);
                udp->source = rule->new_src_port;
                modified = 1;
            }
            if (rule->new_dst_port && udp->dest != rule->new_dst_port) {
                if (udp->check)
                    udp->check = csum_update(udp->check, udp->dest, rule->new_dst_port);
                udp->dest = rule->new_dst_port;
                modified = 1;
            }
        }
    }

    // === 3. IP address modification ===
    if (rule->ip_mod_enable) {
        if (rule->new_src_ip && ip->saddr != rule->new_src_ip) {
            ip->check = csum_update32(ip->check, ip->saddr, rule->new_src_ip);

            // Update L4 pseudo-header checksum
            if (protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = l4;
                if ((void *)(tcp + 1) <= data_end)
                    tcp->check = csum_update32(tcp->check, ip->saddr, rule->new_src_ip);
            } else if (protocol == IPPROTO_UDP && l4 + sizeof(struct udphdr) <= data_end) {
                struct udphdr *udp = l4;
                if (udp->check)
                    udp->check = csum_update32(udp->check, ip->saddr, rule->new_src_ip);
            }

            ip->saddr = rule->new_src_ip;
            modified = 1;
        }

        if (rule->new_dst_ip && ip->daddr != rule->new_dst_ip) {
            ip->check = csum_update32(ip->check, ip->daddr, rule->new_dst_ip);

            if (protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = l4;
                if ((void *)(tcp + 1) <= data_end)
                    tcp->check = csum_update32(tcp->check, ip->daddr, rule->new_dst_ip);
            } else if (protocol == IPPROTO_UDP && l4 + sizeof(struct udphdr) <= data_end) {
                struct udphdr *udp = l4;
                if (udp->check)
                    udp->check = csum_update32(udp->check, ip->daddr, rule->new_dst_ip);
            }

            ip->daddr = rule->new_dst_ip;
            modified = 1;
        }
    }

    // === Send event if modified ===
    if (modified) {
        bpf_printk("[TC] ✓ Packet modified, sending event (flags_set=0x%02x)", tcp_flags_set);
        send_pkt_event(skb, protocol, ip->saddr, ip->daddr, src_port, dst_port, tcp_flags_set);
    } else {
        bpf_printk("[TC] No modifications made");
    }

    return TC_ACT_OK;
}

// === Main TC program ===
SEC("classifier")
int tc_pkt_modifier(struct __sk_buff *skb)
{
    // In TC, we don't easily know if we are ingress or egress from the skb
    // without helper calls or metadata. For now, we try to match both
    // but the loader usually attaches us to one side.
    // We can try to infer or just match against direction 'Any' or the specific one.
    // To be safe and flexible, we try to match with direction Ingress(1) then Egress(2)
    // if we don't know. But better: let the rule handle it.
    
    // Pass 2 (Egress) for TC egress hook
    return tc_pkt_modifier_common(skb, 2); 
}
