/* SPDX-License-Identifier: MIT
 * Opt-in SYN-ACK compatibility for one TCP listener, attached using TCX.
 * This changes neither the receiver's TCP state nor the application bytes.
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include "compat.h"

const volatile struct ctfo_config config = {};
#define SEC(s) __attribute__((section(s), used))
#define INLINE static __attribute__((always_inline)) inline
#define __uint(n, v) int (*n)[v]
#define __type(n, v) v *n
#define BE16(v) __builtin_bswap16((__u16)(v))
#define BE32(v) __builtin_bswap32((__u32)(v))

static void *(*lookup)(void *, const void *) = (void *)BPF_FUNC_map_lookup_elem;
static long (*update)(void *, const void *, const void *, __u64) = (void *)BPF_FUNC_map_update_elem;
static long (*erase)(void *, const void *) = (void *)BPF_FUNC_map_delete_elem;
static __u64 (*now_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static long (*load)(const void *, __u32, void *, __u32) = (void *)BPF_FUNC_skb_load_bytes;
static long (*store)(void *, __u32, const void *, __u32, __u64) = (void *)BPF_FUNC_skb_store_bytes;
static long (*csum_replace)(void *, __u32, __u64, __u64, __u64) = (void *)BPF_FUNC_l4_csum_replace;

/* Network byte order throughout the key; IPv4 addresses are zero extended. */
struct flow {
    __u8 client[16], server[16];
    __u16 client_port, server_port;
    __u32 family;
};
struct handshake { __u64 at; __u32 isn; __u32 length; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct flow);
    __type(value, struct handshake);
} ctfo_pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ctfo_counters);
} ctfo_stats SEC(".maps");

INLINE void count(enum ctfo_counter index) {
    __u32 key = 0;
    struct ctfo_counters *c = lookup(&ctfo_stats, &key);
    if (c) c->value[index]++;
}

struct packet {
    struct flow key;
    __u32 tcp, payload_length, seq, ack;
    __u16 header;
    __u8 flags;
};

/* Only ordinary, unfragmented IPv4/IPv6 TCP handshakes are candidates.
 * Other traffic is returned untouched, including IPv6 extension headers.
 * Android's measured path uses these ordinary headers. */
INLINE int parse(struct __sk_buff *skb, struct packet *p, int outgoing) {
    const __u8 *data = (const void *)(long)skb->data;
    const __u8 *end = (const void *)(long)skb->data_end;
    if (data + 14 > end) return 0;
    const __u8 *ip = data + 14;
    __u32 total, ip_length, family;
    if (data[12] == 8 && data[13] == 0) {
        if (ip + 20 > end || ip[9] != 6 || (ip[0] >> 4) != 4) return 0;
        ip_length = (ip[0] & 15) * 4;
        if (ip_length < 20 || (ip[6] & 0x3f) || ip[7]) return 0;
        total = ((__u32)ip[2] << 8) | ip[3];
        family = 4;
    } else if (data[12] == 0x86 && data[13] == 0xdd) {
        if (ip + 40 > end || ip[6] != 6 || (ip[0] >> 4) != 6) return 0;
        ip_length = 40;
        total = 40 + ((__u32)ip[4] << 8) + ip[5];
        family = 6;
    } else return 0;
    const __u8 *tcp = ip + ip_length;
    if (tcp + 20 > end) return 0;
    p->flags = tcp[13];
    /* The usual data path exits here without helpers, state or writes. */
    if (!(p->flags & 2) || (p->flags & 5)) return 0;
    __builtin_memcpy(&p->key.server_port, tcp + (outgoing ? 0 : 2), 2);
    if (p->key.server_port != BE16(config.port)) return 0;
    __builtin_memcpy(&p->key.client_port, tcp + (outgoing ? 2 : 0), 2);
    p->header = (tcp[12] >> 4) * 4;
    if (p->header < 20 || total < ip_length + p->header || total + 14 > skb->len) return 0;
    p->key.family = family;
    if (family == 4) {
        if (ip + 20 > end) return 0;
        __builtin_memcpy(outgoing ? p->key.server : p->key.client, ip + 12, 4);
        __builtin_memcpy(outgoing ? p->key.client : p->key.server, ip + 16, 4);
    } else {
        if (ip + 40 > end) return 0;
        __builtin_memcpy(outgoing ? p->key.server : p->key.client, ip + 8, 16);
        __builtin_memcpy(outgoing ? p->key.client : p->key.server, ip + 24, 16);
    }
    __builtin_memcpy(&p->seq, tcp + 4, 4);
    __builtin_memcpy(&p->ack, tcp + 8, 4);
    p->seq = BE32(p->seq);
    p->ack = BE32(p->ack);
    p->tcp = 14 + ip_length;
    p->payload_length = total - ip_length - p->header;
    return 1;
}

/* The first eight random bytes in our existing private Hello envelope.
 * Remaining randomness, encrypted bytes and all codec modes are unchanged.
 * This is a versioned capability request, not authentication. */
INLINE int marked(struct __sk_buff *skb, const struct packet *p) {
    __u8 h[19];
    if (p->payload_length < 86 || load(skb, p->tcp + p->header, h, sizeof(h))) return 0;
    return h[0] == 22 && h[1] == 3 && h[2] == 1 && h[5] == 1 && h[6] == 0 &&
        h[9] == 3 && h[10] == 3 &&
        h[11] == 'C' && h[12] == 'T' && h[13] == 'F' && h[14] == 'O' &&
        h[15] == 1 && h[16] == 0 && h[17] == 0 && h[18] == 0;
}

SEC("tcx/ingress") int remember_syn(struct __sk_buff *skb) {
    struct packet p = {};
    if (!parse(skb, &p, 0) || (p.flags & 16)) return TC_ACT_UNSPEC;
    if (marked(skb, &p)) {
        struct handshake h = { .at = now_ns(), .isn = p.seq, .length = p.payload_length };
        count(CTFO_MARKED_SYN);
        /* Do not allow the receiver to acknowledge marked early data when
         * its corresponding compatibility state could not be recorded. */
        if (update(&ctfo_pending, &p.key, &h, BPF_ANY)) {
            count(CTFO_STATE_ERROR);
            return TC_ACT_SHOT;
        }
    } else {
        struct handshake *old = lookup(&ctfo_pending, &p.key);
        /* Keep the same handshake across a SYN retransmission without data;
         * never apply a previous connection's state to a new initial sequence. */
        if (old && (old->isn != p.seq || now_ns() - old->at > 120000000000ULL))
            erase(&ctfo_pending, &p.key);
    }
    return TC_ACT_UNSPEC;
}

SEC("tcx/egress") int adapt_synack(struct __sk_buff *skb) {
    struct packet p = {};
    if (!parse(skb, &p, 1) || !(p.flags & 16)) return TC_ACT_UNSPEC;
    struct handshake *h = lookup(&ctfo_pending, &p.key);
    if (!h) return TC_ACT_UNSPEC;
    if (now_ns() - h->at > 120000000000ULL) {
        erase(&ctfo_pending, &p.key);
        count(CTFO_EXPIRED_STATE);
        return TC_ACT_UNSPEC;
    }
    /* Only adapt a SYN-ACK which confirms the precise prefix we observed.
     * Cold-cookie / rejected-data SYN-ACKs already acknowledge only SYN. */
    __u32 target = h->isn + 1;
    if (p.ack != target + h->length) {
        if (p.ack == target) count(CTFO_REJECTED_EARLY_DATA);
        return TC_ACT_UNSPEC;
    }
    __u32 old_ack = BE32(p.ack), new_ack = BE32(target);
    if (csum_replace(skb, p.tcp + 16, old_ack, new_ack, 4) ||
        store(skb, p.tcp + 8, &new_ack, 4, 0)) {
        count(CTFO_WRITE_ERROR);
        return TC_ACT_SHOT;
    }
    count(CTFO_ADAPTED_SYNACK);
    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "MIT";
