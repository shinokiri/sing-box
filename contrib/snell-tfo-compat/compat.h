/* SPDX-License-Identifier: MIT */
#ifndef SNELL_TFO_COMPAT_H
#define SNELL_TFO_COMPAT_H
#include <linux/types.h>
#define CTFO_MAGIC 0x4f465443U
#define CTFO_ABI 1U
#define CTFO_CAPACITY 16384U
struct ctfo_config {
    __u32 magic, abi, port, ifindex;
    __u8 build[32];
};
enum ctfo_counter {
    CTFO_MARKED_SYN,
    CTFO_STATE_ERROR,
    CTFO_ADAPTED_SYNACK,
    CTFO_WRITE_ERROR,
    CTFO_EXPIRED_STATE,
    CTFO_REJECTED_EARLY_DATA,
    CTFO_COUNTERS
};
struct ctfo_counters { __u64 value[CTFO_COUNTERS]; };
#endif
