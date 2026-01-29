#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// Constants
#ifndef EPERM
#define EPERM 1
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
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

// Event types
#define EVENT_FILE 1
#define EVENT_PROC 2
#define EVENT_NET 3
#define EVENT_DEBUG 4

// Operating modes
#define MODE_MONITOR 0
#define MODE_PROTECT 1

// Actions
#define ACTION_ALLOW 0
#define ACTION_DENY 1

// Unified Event Structure (matches ebpf-common/src/event.rs)
struct unified_event {
    __u8 type;
    union {
        struct {
            __u32 pid;
            __u32 uid;
            __u8 blocked;
            char comm[16];
            char path[64];
        } monitor;
        struct {
            __u8 protocol;
            __u8 tcp_flags_set;
            __u32 src_ip;
            __u32 dst_ip;
            __u16 src_port;
            __u16 dst_port;
            __u8 padding[2];
        } network;
        char msg[89];
    };
};

// --- Maps ---

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} event_ringbuf SEC(".maps");

struct path_buffer {
    char buf[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct path_buffer);
} path_scratch SEC(".maps");

struct pattern_key {
    char pattern[32];
};

struct rule_entry {
    __u8 action;
    __u8 event_type;
    __u8 mode;
    __u8 ops_mask;
    __u8 padding[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct pattern_key);
    __type(value, struct rule_entry);
} pattern_rules SEC(".maps");

// Network maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);  // dst_port in network byte order
    __type(value, __u8); // 1 = blocked
} block_rules SEC(".maps");

struct pkt_mod_key {
    __u8 protocol;    // 6=TCP, 17=UDP, 1=ICMP, 0=any
    __u8 direction;   // 0=any, 1=ingress, 2=egress
    __u8 padding[2];
    __u32 dst_ip;     // Network byte order, 0 = any
    __u16 src_port;   // Network byte order, 0 = any
    __u16 dst_port;   // Network byte order, 0 = any
} __attribute__((packed));

struct pkt_mod_value {
    __u8 tcp_flags_enable;
    __u8 tcp_set_ecn_echo;
    __u8 tcp_set_cwr;
    __u8 tcp_set_reserved;
    __u8 tcp_flags_mask;
    __u8 tcp_flags_value;
    __u8 reserved_bits_mask;
    __u8 reserved_bits_value;
    __u8 port_mod_enable;
    __u16 new_src_port;
    __u16 new_dst_port;
    __u8 ip_mod_enable;
    __u32 new_src_ip;
    __u32 new_dst_ip;
    __u32 allowed_ip;
    __u32 allowed_mask;
    __u8 padding[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct pkt_mod_key);
    __type(value, struct pkt_mod_value);
} pkt_mod_rules SEC(".maps");

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
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct reverse_key);
    __type(value, struct reverse_value);
} reverse_rules SEC(".maps");

// --- Helpers ---

static __always_inline void send_monitor_event(__u8 type, const char *path, __u8 blocked) {
    struct unified_event *e = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*e), 0);
    if (!e) return;

    e->type = type;
    e->monitor.pid = bpf_get_current_pid_tgid() >> 32;
    e->monitor.uid = bpf_get_current_uid_gid();
    e->monitor.blocked = blocked;

    if (path) {
        __builtin_memcpy(e->monitor.path, path, sizeof(e->monitor.path));
    }

    bpf_get_current_comm(e->monitor.comm, sizeof(e->monitor.comm));
    bpf_ringbuf_submit(e, 0);
}

static __always_inline void send_network_event(__u8 protocol, __u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port, __u8 flags_set) {
    struct unified_event *e = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*e), 0);
    if (!e) return;

    e->type = EVENT_NET;
    e->network.protocol = protocol;
    e->network.tcp_flags_set = flags_set;
    e->network.src_ip = bpf_ntohl(src_ip);
    e->network.dst_ip = bpf_ntohl(dst_ip);
    e->network.src_port = bpf_ntohs(src_port);
    e->network.dst_port = bpf_ntohs(dst_port);

    bpf_ringbuf_submit(e, 0);
}

static __always_inline void send_debug_log(const char *msg) {
    struct unified_event *e = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*e), 0);
    if (!e) return;

    e->type = EVENT_DEBUG;
    __builtin_memcpy(e->msg, msg, sizeof(e->msg) < 89 ? sizeof(e->msg) : 89);
    bpf_ringbuf_submit(e, 0);
}

static __always_inline struct rule_entry *check_pattern_rules(const char *path, __u8 event_type) {
    struct pattern_key key = {};
    __builtin_memcpy(key.pattern, path, sizeof(key.pattern));
    return bpf_map_lookup_elem(&pattern_rules, &key);
}

// Checksum helpers (RFC 1624)
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

static __always_inline struct pkt_mod_value *find_net_rule(__u8 protocol, __u8 direction, __u32 dst_ip, __u16 src_port, __u16 dst_port) {
    struct pkt_mod_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.protocol = protocol;
    key.direction = direction;
    key.dst_ip = dst_ip;
    key.src_port = src_port;
    key.dst_port = dst_port;

    // 1. Try exact match
    struct pkt_mod_value *rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    // 2. Try wildcard src_port
    key.src_port = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    // 3. Try wildcard IP + exact src_port
    key.src_port = src_port;
    key.dst_ip = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    // 4. Try wildcard IP + wildcard src_port
    key.src_port = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    // 5. Try any direction + wildcard IP + wildcard src_port
    key.direction = 0;
    rule = bpf_map_lookup_elem(&pkt_mod_rules, &key);
    if (rule) return rule;

    return NULL;
}

// --- LSM Hooks ---

SEC("lsm.s/file_open")
int BPF_PROG(enforce_file_open, struct file *file) {
    __u32 zero = 0;
    struct path_buffer *scratch = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!scratch) return 0;

    char *buf = scratch->buf;
    __builtin_memset(buf, 0, 256);

    if (bpf_d_path(&file->f_path, buf, 256) < 0) return 0;

    struct rule_entry *rule = check_pattern_rules(buf, EVENT_FILE);
    if (rule && rule->action == ACTION_DENY && rule->mode == MODE_PROTECT) {
        __u8 match = 0;
        __u32 flags = BPF_CORE_READ(file, f_flags);
        __u32 acc_mode = flags & 3; // O_ACCMODE
        
        // Bit 0: Read (O_RDONLY=0, O_RDWR=2)
        if ((rule->ops_mask & 1) && (acc_mode == 0 || acc_mode == 2)) match = 1;
        // Bit 1: Write (O_WRONLY=1, O_RDWR=2)
        if ((rule->ops_mask & 2) && (acc_mode == 1 || acc_mode == 2)) match = 1;
        // Bit 2: Create (O_CREAT = 0100 octal = 64 decimal)
        if ((rule->ops_mask & 4) && (flags & 64)) match = 1;

        if (match) {
            send_monitor_event(EVENT_FILE, buf, 1);
            return -EPERM;
        }
    }

    return 0;
}

SEC("lsm.s/bprm_check_security")
int BPF_PROG(enforce_bprm_check_security, struct linux_binprm *bprm) {
    __u32 zero = 0;
    struct path_buffer *scratch = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!scratch) return 0;

    char *buf = scratch->buf;
    __builtin_memset(buf, 0, 256);

    if (bpf_probe_read_kernel_str(buf, 256, bprm->filename) < 0) return 0;

    // 1. Try match full path
    struct rule_entry *rule = check_pattern_rules(buf, EVENT_PROC);
    
    // 2. If not matched, try match basename (comm)
    if (!rule) {
        const char *filename = buf;
        const char *last_slash = NULL;
        #pragma unroll
        for (int i = 0; i < 64; i++) {
            if (buf[i] == '/') last_slash = &buf[i];
            if (buf[i] == '\0') break;
        }
        if (last_slash) {
            rule = check_pattern_rules(last_slash + 1, EVENT_PROC);
        }
    }

    if (rule && rule->action == ACTION_DENY && rule->mode == MODE_PROTECT) {
        send_monitor_event(EVENT_PROC, buf, 1);
        return -EPERM;
    }

    return 0;
}

SEC("lsm.s/path_mknod")
int BPF_PROG(enforce_path_mknod, struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev) {
    __u32 zero = 0;
    struct path_buffer *scratch = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!scratch) return 0;

    char *buf = scratch->buf;
    __builtin_memset(buf, 0, 256);

    // Build path for the new file
    struct path p;
    p.dentry = dentry;
    p.mnt = BPF_CORE_READ(dir, mnt);
    
    if (bpf_d_path(&p, buf, 256) < 0) {
        // Fallback: use filename only
        const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
        if (bpf_probe_read_kernel_str(buf, 64, name_ptr) < 0) return 0;
    }

    struct rule_entry *rule = check_pattern_rules(buf, EVENT_FILE);
    if (rule && rule->action == ACTION_DENY && rule->mode == MODE_PROTECT) {
        // Check if Create operation (bit 2) is controlled
        if (rule->ops_mask & 4) {
            send_monitor_event(EVENT_FILE, buf, 1);
            return -EPERM;
        }
    }

    return 0;
}

SEC("lsm.s/inode_create")
int BPF_PROG(enforce_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode) {
    __u32 zero = 0;
    struct path_buffer *scratch = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!scratch) return 0;

    char *buf = scratch->buf;
    __builtin_memset(buf, 0, 256);

    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    if (bpf_probe_read_kernel_str(buf, 64, name_ptr) < 0) return 0;

    struct rule_entry *rule = check_pattern_rules(buf, EVENT_FILE);
    if (rule && rule->action == ACTION_DENY && rule->mode == MODE_PROTECT) {
        // Check if Create operation (bit 2) is controlled
        if (rule->ops_mask & 4) {
            send_monitor_event(EVENT_FILE, buf, 1);
            return -EPERM;
        }
    }

    return 0;
}

SEC("lsm.s/inode_unlink")
int BPF_PROG(enforce_inode_unlink, struct inode *dir, struct dentry *dentry) {
    __u32 zero = 0;
    struct path_buffer *scratch = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!scratch) return 0;

    char *buf = scratch->buf;
    __builtin_memset(buf, 0, 256);

    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    if (bpf_probe_read_kernel_str(buf, 64, name_ptr) < 0) return 0;

    struct rule_entry *rule = check_pattern_rules(buf, EVENT_FILE);
    if (rule && rule->action == ACTION_DENY && rule->mode == MODE_PROTECT) {
        // Check if Delete operation (bit 3) is controlled
        if (rule->ops_mask & 8) {
            send_monitor_event(EVENT_FILE, buf, 1);
            return -EPERM;
        }
    }

    return 0;
}

// --- Network Hooks ---

// XDP hook
SEC("xdp")
int xdp_packet_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)eth + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __u8 protocol = ip->protocol;
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;

    if (protocol != 6 && protocol != 17) return XDP_PASS;

    __u16 src_port = 0, dst_port = 0;
    void *l4_hdr = (void *)ip + (ip->ihl * 4);

    if (protocol == 6) {
        struct tcphdr *tcp = l4_hdr;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        src_port = tcp->source;
        dst_port = tcp->dest;
    } else {
        struct udphdr *udp = l4_hdr;
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        src_port = udp->source;
        dst_port = udp->dest;
    }

    // 1. Check block rules
    __u16 block_key = bpf_ntohs(dst_port);
    __u8 *blocked = bpf_map_lookup_elem(&block_rules, &block_key);
    if (blocked && *blocked) {
        send_network_event(protocol, src_ip, dst_ip, src_port, dst_port, 0x80);
        return XDP_DROP;
    }

    // 2. Try find mod rule (Ingress = 1)
    struct pkt_mod_value *rule = find_net_rule(protocol, 1, dst_ip, src_port, dst_port);
    if (!rule) {
        // --- Try handle reverse traffic exactly like forward.bpf.c ---
        struct reverse_key r_key;
        __builtin_memset(&r_key, 0, sizeof(r_key));
        r_key.target_ip = src_ip;
        r_key.target_port = src_port;
        r_key.client_ip = dst_ip;
        r_key.client_port = dst_port;

        struct reverse_value *r_val = bpf_map_lookup_elem(&reverse_rules, &r_key);
        if (r_val) {
             if (protocol == 6) {
                 struct tcphdr *tcp = l4_hdr;
                 if ((void *)(tcp + 1) > data_end) return XDP_PASS;
                 // 1. Translate Source: target -> local
                 csum_replace4(&tcp->check, src_ip, r_val->local_ip);
                 csum_replace2(&tcp->check, src_port, r_val->local_port);
                 tcp->source = r_val->local_port;
                 // 2. Translate Destination: agent -> client
                 csum_replace4(&tcp->check, dst_ip, r_val->client_ip);
             } else {
                 struct udphdr *udp = l4_hdr;
                 if ((void *)(udp + 1) > data_end) return XDP_PASS;
                 if (udp->check) {
                     csum_replace4(&udp->check, src_ip, r_val->local_ip);
                     csum_replace2(&udp->check, src_port, r_val->local_port);
                     csum_replace4(&udp->check, dst_ip, r_val->client_ip);
                 }
                 udp->source = r_val->local_port;
             }
             csum_replace4(&ip->check, src_ip, r_val->local_ip);
             ip->saddr = r_val->local_ip;
             csum_replace4(&ip->check, dst_ip, r_val->client_ip);
             ip->daddr = r_val->client_ip;
             return XDP_PASS;
        }
        return XDP_PASS;
    }

    // 3. Mod rule hit: Forward + SNAT
    // Determine target IP and port
    __u32 target_ip = dst_ip;
    if (rule->ip_mod_enable && rule->new_dst_ip != 0) {
        target_ip = rule->new_dst_ip;
    }
    __u16 target_port = rule->port_mod_enable ? rule->new_dst_port : dst_port;

    // Determine if we should SNAT (only for remote forwarding)
    __u32 new_src_ip = src_ip;
    if (rule->ip_mod_enable && rule->new_dst_ip != 0) {
        new_src_ip = dst_ip; // SNAT to local IP
    }

    // Store reverse mapping for return traffic
    struct reverse_key rev_k;
    __builtin_memset(&rev_k, 0, sizeof(rev_k));
    rev_k.target_ip = target_ip;
    rev_k.target_port = target_port;
    rev_k.client_ip = new_src_ip; 
    rev_k.client_port = src_port;
    
    struct reverse_value rev_v;
    __builtin_memset(&rev_v, 0, sizeof(rev_v));
    rev_v.local_ip = dst_ip;
    rev_v.local_port = dst_port;
    rev_v.client_ip = src_ip;
    
    bpf_map_update_elem(&reverse_rules, &rev_k, &rev_v, BPF_ANY);

    bpf_printk("[XDP] Forward: %pI4 -> %pI4", &src_ip, &dst_ip);
    bpf_printk("[XDP]   Target: %pI4:%u, SNAT: %pI4", &target_ip, bpf_ntohs(target_port), &new_src_ip);

    if (protocol == 6) {
        struct tcphdr *tcp = l4_hdr;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        // DNAT
        if (target_ip != dst_ip) {
            csum_replace4(&tcp->check, dst_ip, target_ip);
        }
        if (target_port != dst_port) {
            csum_replace2(&tcp->check, dst_port, target_port);
            tcp->dest = target_port;
        }
        // SNAT
        if (new_src_ip != src_ip) {
            csum_replace4(&tcp->check, src_ip, new_src_ip);
        }
    } else {
        struct udphdr *udp = l4_hdr;
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        if (udp->check) {
            if (target_ip != dst_ip) csum_replace4(&udp->check, dst_ip, target_ip);
            if (target_port != dst_port) csum_replace2(&udp->check, dst_port, target_port);
            if (new_src_ip != src_ip) csum_replace4(&udp->check, src_ip, new_src_ip);
        }
        udp->dest = target_port;
    }
    
    if (target_ip != dst_ip) {
        csum_replace4(&ip->check, dst_ip, target_ip);
        ip->daddr = target_ip;
    }
    if (new_src_ip != src_ip) {
        csum_replace4(&ip->check, src_ip, new_src_ip);
        ip->saddr = new_src_ip;
    }

    send_network_event(protocol, src_ip, dst_ip, src_port, dst_port, 0x40);
    return XDP_PASS;
}

// TC hook
SEC("classifier")
int tc_packet_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    __u8 protocol = ip->protocol;
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u16 src_port = 0, dst_port = 0;
    void *l4 = (void *)ip + (ip->ihl * 4);

    if (protocol == 6) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
        src_port = tcp->source;
        dst_port = tcp->dest;
    } else if (protocol == 17) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) return TC_ACT_OK;
        src_port = udp->source;
        dst_port = udp->dest;
    } else {
        return TC_ACT_OK;
    }

    // Check block
    __u16 block_key = bpf_ntohs(dst_port);
    __u8 *blocked = bpf_map_lookup_elem(&block_rules, &block_key);
    if (blocked && *blocked) {
        send_network_event(protocol, src_ip, dst_ip, src_port, dst_port, 0x80);
        return TC_ACT_SHOT;
    }

    // --- Reverse Mapping Check (for return traffic) ---
    struct reverse_key r_key;
    __builtin_memset(&r_key, 0, sizeof(r_key));
    r_key.target_ip = src_ip;
    r_key.target_port = src_port;
    r_key.client_ip = dst_ip;
    r_key.client_port = dst_port;

    struct reverse_value *r_val = bpf_map_lookup_elem(&reverse_rules, &r_key);
    if (r_val) {
        bpf_printk("[TC] Reverse NAT: %pI4 -> %pI4", &src_ip, &dst_ip);
        bpf_printk("[TC]   Ports: %u -> %u", bpf_ntohs(src_port), bpf_ntohs(dst_port));
        bpf_printk("[TC]   => %pI4:%u",
                   &r_val->local_ip, bpf_ntohs(r_val->local_port));

        if (protocol == 6) {
            struct tcphdr *tcp = l4;
            if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
            // 1. Translate Source: target -> local
            if (src_ip != r_val->local_ip) csum_replace4(&tcp->check, src_ip, r_val->local_ip);
            if (src_port != r_val->local_port) {
                csum_replace2(&tcp->check, src_port, r_val->local_port);
                tcp->source = r_val->local_port;
            }
            // 2. Translate Destination: agent -> client
            if (dst_ip != r_val->client_ip) csum_replace4(&tcp->check, dst_ip, r_val->client_ip);
            // Dest port remains same (client_port == dst_port)
        } else {
            struct udphdr *udp = l4;
            if ((void *)(udp + 1) > data_end) return TC_ACT_OK;
            if (udp->check) {
                if (src_ip != r_val->local_ip) csum_replace4(&udp->check, src_ip, r_val->local_ip);
                if (src_port != r_val->local_port) csum_replace2(&udp->check, src_port, r_val->local_port);
                if (dst_ip != r_val->client_ip) csum_replace4(&udp->check, dst_ip, r_val->client_ip);
            }
            udp->source = r_val->local_port;
        }
        
        if (src_ip != r_val->local_ip) {
            csum_replace4(&ip->check, src_ip, r_val->local_ip);
            ip->saddr = r_val->local_ip;
        }
        if (dst_ip != r_val->client_ip) {
            csum_replace4(&ip->check, dst_ip, r_val->client_ip);
            ip->daddr = r_val->client_ip;
        }
        
        send_network_event(protocol, src_ip, dst_ip, src_port, dst_port, 0x40);
        return TC_ACT_OK;
    }

    // Find rule (Egress = 2 for TC egress)
    struct pkt_mod_value *rule = find_net_rule(protocol, 2, dst_ip, src_port, dst_port);
    if (!rule) return TC_ACT_OK;

    int modified = 0;
    if (protocol == 6 && rule->tcp_flags_enable) {
        struct tcphdr *tcp = l4;
        __u8 *flags_byte = (__u8 *)tcp + 13;
        __u8 old_flags = *flags_byte;
        __u8 new_flags = old_flags;
        if (rule->tcp_set_cwr) new_flags |= (1 << 7);
        if (rule->tcp_set_ecn_echo) new_flags |= (1 << 6);
        if (rule->tcp_flags_mask) new_flags = (new_flags & ~rule->tcp_flags_mask) | (rule->tcp_flags_value & rule->tcp_flags_mask);
        
        if (old_flags != new_flags) {
            csum_replace2(&tcp->check, old_flags, new_flags);
            *flags_byte = new_flags;
            modified = 1;
        }
    }

    if (rule->port_mod_enable) {
        if (protocol == 6) {
            struct tcphdr *tcp = l4;
            if (rule->new_dst_port && tcp->dest != rule->new_dst_port) {
                csum_replace2(&tcp->check, tcp->dest, rule->new_dst_port);
                tcp->dest = rule->new_dst_port;
                modified = 1;
            }
        }
    }

    if (modified) send_network_event(protocol, src_ip, dst_ip, src_port, dst_port, 0x40);
    return TC_ACT_OK;
}

// --- Cgroup Connect Hook ---

SEC("cgroup/connect4")
int enforce_connect4(struct bpf_sock_addr *ctx) {
    if (ctx->family != 2) return 1; // AF_INET

    __u32 dst_ip = ctx->user_ip4;
    __u16 dst_port = ctx->user_port;
    __u8 protocol = (ctx->type == 1) ? 6 : 17; // SOCK_STREAM -> TCP, else -> UDP

    // Match rules (conceptually egress from app, so we check direction=0 or 2)
    struct pkt_mod_value *rule = find_net_rule(protocol, 0, dst_ip, 0, dst_port);
    if (!rule) {
        rule = find_net_rule(protocol, 2, dst_ip, 0, dst_port);
    }
    
    // Also check Ingress rules if user is using unified config for "forwarding"
    if (!rule) {
        rule = find_net_rule(protocol, 1, dst_ip, 0, dst_port);
    }

    if (rule) {
        if (rule->port_mod_enable && rule->new_dst_port) {
            ctx->user_port = rule->new_dst_port;
        }
        if (rule->ip_mod_enable && rule->new_dst_ip) {
            ctx->user_ip4 = rule->new_dst_ip;
        }
        send_network_event(protocol, 0, bpf_ntohl(dst_ip), 0, bpf_ntohs(dst_port), 0x20);
    }

    return 1;
}
