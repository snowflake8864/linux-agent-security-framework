#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Error codes
#define EPERM 1

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

// Event structure
struct event {
       __u8 type;
   union {
     struct {
       __u32 pid;
       __u32 uid;
       __u8 blocked;
       char comm[16];
       char path[64];
     };
     char msg[89];
   };
};



// Structs
struct path_buffer {
    char buf[256];
};

struct pattern_key {
    char pattern[32];
};

struct rule_entry {
    __u8 action;
    __u8 event_type;
    __u8 padding[6];
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct path_buffer);
} path_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct pattern_key);
    __type(value, struct rule_entry);
} pattern_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} mode_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} event_ringbuf SEC(".maps");

// Helper functions
static __always_inline __u8 get_mode() {
    __u32 key = 0;
    __u8 *mode = bpf_map_lookup_elem(&mode_map, &key);
    return mode ? *mode : MODE_MONITOR;
}

static __always_inline long get_dentry_path(struct dentry *dentry, char *buf, int size) {
    struct path path;
    BPF_CORE_READ_INTO(&path, dentry, d_parent);
    return bpf_d_path(&path, buf, size);
}

static __always_inline struct rule_entry *check_pattern_rules(const char *path, __u8 event_type) {
    struct pattern_key key = {};
    __builtin_memcpy(key.pattern, path, sizeof(key.pattern));
    return bpf_map_lookup_elem(&pattern_rules, &key);
}

// Helper: send event
static __always_inline void send_event_ex(__u8 type, const char *action, const char *path, __u8 blocked) {
    struct event *e = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*e), 0);
    if (!e) return;

    e->type = type;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->blocked = blocked;

    if (path) {
        __builtin_memcpy(e->path, path, sizeof(e->path));
    }

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
}

// Helper: send debug log
static __always_inline void send_debug_log(const char *prefix, const char *msg) {
    struct event *e = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*e), 0);
    if (!e) return;

    e->type = EVENT_DEBUG;
    __builtin_snprintf(e->msg, sizeof(e->msg), "%s: %s", prefix, msg);
    bpf_ringbuf_submit(e, 0);
}

// LSM hook: file_open - block file access BEFORE it happens
SEC("lsm/file_open")
int enforce_file_open(struct file *file)
{
    __u32 zero = 0;
    struct path_buffer *scratch = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!scratch)
        return 0;

    char *buf = scratch->buf;
    __builtin_memset(buf, 0, 256);

    // Get path from file
    if (bpf_d_path(&file->f_path, buf, 256) < 0) {
        return 0; // Allow if can't get path
    }

    __u8 mode_val = get_mode();
    struct rule_entry *rule = check_pattern_rules(buf, EVENT_FILE);
    if (rule && rule->action == ACTION_DENY && mode_val == MODE_PROTECT) {
        send_event_ex(EVENT_FILE, "OPEN", buf, 1);
        return -EPERM;
    }

    return 0;
}



// LSM hook: bprm_check_security - block process execution BEFORE it happens
SEC("lsm/bprm_check_security")
int enforce_bprm_check_security(struct linux_binprm *bprm)
{
    __u32 zero = 0;
    struct path_buffer *scratch = bpf_map_lookup_elem(&path_scratch, &zero);
    if (!scratch)
        return 0;

    char *buf = scratch->buf;
    __builtin_memset(buf, 0, 256);

    // Get executable path
    if (bpf_probe_read_kernel_str(buf, 256, bprm->filename) < 0) {
        return 0;
    }

// LSM bprm_check_security removed for now

    return 0;
}

