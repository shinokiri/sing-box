/* SPDX-License-Identifier: MIT
 * One-shot TCX loader. Pinned BPF links, not a resident process, own the hooks.
 */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>
#include "compat.h"
#include "embedded.h"

#define ROOT "/sys/fs/bpf/snell-tfo-compat"
#define LOCK_ROOT "/run/snell-tfo-compat"
enum pin { CONFIG, PENDING, STATS, INGRESS, EGRESS, PINS };
static const char *const names[] = {"config", "pending", "stats", "ingress", "egress"};
static const char *const counters[] = {
    "marked_syn", "state_error", "adapted_synack", "write_error", "expired_state", "rejected_early_data"
};
struct instance {
    char directory[256];
    int fd[PINS];
    __u32 id[PINS], program[2];
    struct ctfo_config config;
    bool exists, complete, attached[2];
};

static int error(const char *operation) {
    fprintf(stderr, "snell-tfo-compat: %s: %s\n", operation, strerror(errno));
    return -1;
}

static int refuse(const char *reason) {
    fprintf(stderr, "snell-tfo-compat: %s\n", reason);
    errno = EINVAL;
    return -1;
}

static int directory(const char *path, bool create) {
    struct stat s;
    if (create && mkdir(path, 0700) && errno != EEXIST) return error(path);
    if (lstat(path, &s)) return error(path);
    if (!S_ISDIR(s.st_mode) || s.st_uid || (s.st_mode & 0077))
        return refuse("state directory must be a root-owned private directory");
    return 0;
}

static void pin_path(const struct instance *s, enum pin pin, char path[320]) {
    snprintf(path, 320, "%s/%s", s->directory, names[pin]);
}

static void close_instance(struct instance *s) {
    for (int i = 0; i < PINS; i++) {
        if (s->fd[i] >= 0) close(s->fd[i]);
        s->fd[i] = -1;
    }
}

static int map_info(int fd, struct bpf_map_info *info) {
    __u32 size = sizeof(*info);
    memset(info, 0, size);
    return bpf_obj_get_info_by_fd(fd, info, &size);
}

static int check_map(struct instance *s, enum pin pin, __u32 type,
                     __u32 key_size, __u32 value_size, __u32 max_entries) {
    if (s->fd[pin] < 0) return 0;
    struct bpf_map_info info;
    if (map_info(s->fd[pin], &info)) return error("inspect map");
    if (info.type != type || info.key_size != key_size ||
        info.value_size != value_size || info.max_entries != max_entries)
        return refuse("unexpected pinned map; no hooks were removed");
    s->id[pin] = info.id;
    return 0;
}

static int check_link(struct instance *s, enum pin pin) {
    if (s->fd[pin] < 0) return 0;
    struct bpf_link_info link = {};
    __u32 size = sizeof(link);
    if (bpf_obj_get_info_by_fd(s->fd[pin], &link, &size)) return error("inspect link");
    __u32 type = pin == INGRESS ? BPF_TCX_INGRESS : BPF_TCX_EGRESS;
    if (link.type != BPF_LINK_TYPE_TCX || link.tcx.attach_type != type ||
        (link.tcx.ifindex && link.tcx.ifindex != s->config.ifindex))
        return refuse("unexpected pinned link; no hooks were removed");
    int fd = bpf_prog_get_fd_by_id(link.prog_id);
    if (fd < 0) return error("open pinned program");
    struct bpf_prog_info prog = {};
    __u32 maps[16] = {};
    prog.nr_map_ids = 16;
    prog.map_ids = (uintptr_t)maps;
    size = sizeof(prog);
    int rc = bpf_obj_get_info_by_fd(fd, &prog, &size);
    close(fd);
    if (rc) return error("inspect pinned program");
    const char *name = pin == INGRESS ? "remember_syn" : "adapt_synack";
    if (prog.type != BPF_PROG_TYPE_SCHED_CLS || strcmp(prog.name, name) || prog.nr_map_ids > 16)
        return refuse("unexpected pinned program; no hooks were removed");
    for (int i = CONFIG; i <= STATS; i++) {
        if (s->fd[i] < 0) continue;
        bool found = false;
        for (__u32 j = 0; j < prog.nr_map_ids; j++) found |= maps[j] == s->id[i];
        if (!found) return refuse("pinned link belongs to a different map set");
    }
    s->id[pin] = link.id;
    s->program[pin - INGRESS] = link.prog_id;
    s->attached[pin - INGRESS] = link.tcx.ifindex != 0;
    return 0;
}

/* Validate the entire owned instance before detaching anything. An incomplete
 * instance with its immutable ownership map can be repaired after interruption.
 */
static int inspect(struct instance *s, unsigned port) {
    DIR *d = opendir(s->directory);
    if (!d) return errno == ENOENT ? 0 : error("open instance directory");
    s->exists = true;
    if (directory(s->directory, false)) { closedir(d); return -1; }
    struct dirent *entry;
    while ((entry = readdir(d))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        int i;
        for (i = 0; i < PINS && strcmp(entry->d_name, names[i]); i++) {}
        if (i == PINS) { closedir(d); return refuse("unknown entry in instance directory"); }
        char path[320]; pin_path(s, i, path);
        struct stat st;
        if (lstat(path, &st) || !S_ISREG(st.st_mode) || st.st_uid) {
            closedir(d); return refuse("unsafe pin path");
        }
        s->fd[i] = bpf_obj_get(path);
        if (s->fd[i] < 0) { closedir(d); return error("open pin"); }
    }
    closedir(d);
    int present = 0;
    for (int i = 0; i < PINS; i++) present += s->fd[i] >= 0;
    if (!present) return 0;
    if (s->fd[CONFIG] < 0) return refuse("missing ownership map; refusing to remove unknown state");
    if (check_map(s, CONFIG, BPF_MAP_TYPE_ARRAY, 4, sizeof(s->config), 1)) return -1;
    __u32 zero = 0;
    if (bpf_map_lookup_elem(s->fd[CONFIG], &zero, &s->config)) return error("read configuration");
    if (s->config.magic != CTFO_MAGIC || s->config.abi != CTFO_ABI || s->config.port != port || !s->config.ifindex)
        return refuse("ownership map does not match this instance");
    if (check_map(s, PENDING, BPF_MAP_TYPE_LRU_HASH, 40, 16, CTFO_CAPACITY) ||
        check_map(s, STATS, BPF_MAP_TYPE_PERCPU_ARRAY, 4, sizeof(struct ctfo_counters), 1) ||
        check_link(s, INGRESS) || check_link(s, EGRESS)) return -1;
    s->complete = present == PINS;
    return 0;
}

static int remove_instance(struct instance *s) {
    /* Stop accepting marked SYNs before removing the SYN-ACK adaptation. */
    for (int i = INGRESS; i <= EGRESS; i++) {
        if (s->fd[i] < 0) continue;
        if (bpf_link_detach(s->fd[i]) && errno != ENOLINK && errno != ENOENT)
            return error("detach owned TCX link");
    }
    const enum pin order[] = {INGRESS, EGRESS, PENDING, STATS, CONFIG};
    for (unsigned i = 0; i < sizeof(order)/sizeof(order[0]); i++) {
        char path[320]; pin_path(s, order[i], path);
        if (unlink(path) && errno != ENOENT) return error("unpin owned object");
    }
    close_instance(s);
    if (rmdir(s->directory) && errno != ENOENT) return error("remove instance directory");
    s->exists = false;
    return 0;
}

static void build_string(const __u8 build[32], char hex[65]) {
    for (int i = 0; i < 32; i++) snprintf(hex + 2*i, 3, "%02x", build[i]);
}

static int report(const struct instance *s, const char *interface, unsigned port, unsigned ifindex) {
    struct ctfo_counters total = {};
    if (s->fd[STATS] >= 0) {
        int n = libbpf_num_possible_cpus();
        if (n <= 0 || n > 1048576) return refuse("invalid CPU count");
        struct ctfo_counters *percpu = calloc(n, sizeof(*percpu));
        if (!percpu) return error("allocate counters");
        __u32 zero = 0;
        int rc = bpf_map_lookup_elem(s->fd[STATS], &zero, percpu);
        if (rc) { free(percpu); return error("read counters"); }
        for (int cpu = 0; cpu < n; cpu++)
            for (int i = 0; i < CTFO_COUNTERS; i++) total.value[i] += percpu[cpu].value[i];
        free(percpu);
    }
    char build[65]; build_string(s->config.build, build);
    bool active = s->complete && s->attached[0] && s->attached[1] && ifindex && ifindex == s->config.ifindex;
    printf("{\"active\":%s,\"interface\":\"%s\",\"port\":%u,\"ifindex\":%u,\"abi\":%u,\"build\":\"%s\",",
           active ? "true" : "false", interface, port, s->config.ifindex, s->config.abi, build);
    printf("\"programs\":{\"ingress\":%u,\"egress\":%u},\"pins\":{", s->program[0], s->program[1]);
    for (int i = 0; i < PINS; i++) printf("%s\"%s\":%u", i ? "," : "", names[i], s->id[i]);
    printf("},\"counters\":{");
    for (int i = 0; i < CTFO_COUNTERS; i++) printf("%s\"%s\":%llu", i ? "," : "", counters[i], (unsigned long long)total.value[i]);
    puts("}}");
    return 0;
}

static int create_instance(struct instance *s, unsigned port, unsigned ifindex) {
    int rc = -1;
    struct bpf_link *links[2] = {};
    struct bpf_object_open_opts opts = {.sz = sizeof(opts), .object_name = "snell_ctfo"};
    struct bpf_object *obj = bpf_object__open_mem(ctfo_object, sizeof(ctfo_object), &opts);
    if (!obj) return error("open embedded BPF object");
    struct bpf_map *config = NULL, *map;
    bpf_object__for_each_map(map, obj) {
        if (bpf_map__is_internal(map) && strstr(bpf_map__name(map), ".rodata")) { config = map; break; }
    }
    struct ctfo_config value = {.magic = CTFO_MAGIC, .abi = CTFO_ABI, .port = port, .ifindex = ifindex};
    memcpy(value.build, ctfo_build, sizeof(value.build));
    if (!config || bpf_map__value_size(config) != sizeof(value) ||
        bpf_map__set_initial_value(config, &value, sizeof(value))) {
        refuse("invalid embedded configuration map"); goto out;
    }
    if (bpf_object__load(obj)) { error("load BPF object"); goto out; }
    if (directory(ROOT, true) || directory(s->directory, true)) goto out;
    s->exists = true;
    struct bpf_map *maps[] = {config, bpf_object__find_map_by_name(obj, "ctfo_pending"), bpf_object__find_map_by_name(obj, "ctfo_stats")};
    for (int i = CONFIG; i <= STATS; i++) {
        char path[320]; pin_path(s, i, path);
        if (!maps[i] || bpf_map__pin(maps[i], path)) { error("pin map"); goto out; }
    }
    /* Egress is ready before ingress can record the first marked SYN. */
    for (int i = EGRESS; i >= INGRESS; i--) {
        const char *name = i == INGRESS ? "remember_syn" : "adapt_synack";
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, name);
        if (!prog) { refuse("missing embedded program"); goto out; }
        links[i - INGRESS] = bpf_program__attach_tcx(prog, ifindex, NULL);
        if (!links[i - INGRESS]) { error("attach TCX program"); goto out; }
        char path[320]; pin_path(s, i, path);
        if (bpf_link__pin(links[i - INGRESS], path)) { error("pin TCX link"); goto out; }
    }
    rc = 0;
out:
    if (rc && s->exists) {
        /* This directory was created under our exclusive lock, not adopted. */
        for (int i = INGRESS; i <= EGRESS; i++)
            if (links[i - INGRESS]) bpf_link__detach(links[i - INGRESS]);
        for (int i = PINS - 1; i >= 0; i--) {
            char path[320]; pin_path(s, i, path); unlink(path);
        }
        rmdir(s->directory);
    }
    for (int i = 0; i < 2; i++) if (links[i]) bpf_link__destroy(links[i]);
    bpf_object__close(obj);
    return rc;
}

static void usage(void) {
    puts("snell-tfo-compat attach|status|detach --interface=NAME --port=PORT\n"
         "Load opt-in SYN-ACK compatibility into TCX; no resident process.\n"
         "Run attach before opening the paired listener and detach after closing it.");
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        char build[65]; build_string(ctfo_build, build);
        printf("snell-tfo-compat abi=%u bpf=%s\n", CTFO_ABI, build); return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--help")) { usage(); return 0; }
    const char *interface = NULL;
    unsigned port = 0;
    if (argc != 4 || (strcmp(argv[1], "attach") && strcmp(argv[1], "status") && strcmp(argv[1], "detach"))) {
        usage(); return 2;
    }
    for (int i = 2; i < argc; i++) {
        if (!strncmp(argv[i], "--interface=", 12) && !interface) interface = argv[i] + 12;
        else if (!strncmp(argv[i], "--port=", 7) && !port) {
            char *end;
            if (!isdigit((unsigned char)argv[i][7])) return 2;
            unsigned long n = strtoul(argv[i] + 7, &end, 10);
            if (*end || !n || n > 65535) return 2;
            port = n;
        } else return 2;
    }
    if (!interface || !*interface || strlen(interface) >= IFNAMSIZ || !port) return 2;
    for (const char *p = interface; *p; p++)
        if (!isalnum((unsigned char)*p) && !strchr("_.:-", *p)) return 2;
    if (!strcmp(interface, ".") || !strcmp(interface, "..")) return 2;
    if (geteuid()) return refuse("root privileges are required") ? 1 : 0;
    unsigned ifindex = if_nametoindex(interface);
    if (!strcmp(argv[1], "attach") && !ifindex) return error("find interface") ? 1 : 0;
    struct statfs fs;
    if (statfs("/sys/fs/bpf", &fs) || fs.f_type != BPF_FS_MAGIC)
        return refuse("/sys/fs/bpf must be mounted as bpffs") ? 1 : 0;
    struct stat parent;
    if (!lstat(ROOT, &parent)) {
        if (directory(ROOT, false)) return 1;
    } else if (errno != ENOENT) return error("inspect state root") ? 1 : 0;
    if (directory(LOCK_ROOT, true)) return 1;
    char lock[256]; snprintf(lock, sizeof(lock), LOCK_ROOT "/%s-%u.lock", interface, port);
    int lockfd = open(lock, O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_RDWR, 0600);
    if (lockfd < 0 || flock(lockfd, LOCK_EX)) return error("lock instance") ? 1 : 0;
    struct instance s = {};
    for (int i = 0; i < PINS; i++) s.fd[i] = -1;
    snprintf(s.directory, sizeof(s.directory), ROOT "/%s-%u", interface, port);
    int rc = inspect(&s, port);
    if (rc) goto out;
    if (!strcmp(argv[1], "status")) { rc = report(&s, interface, port, ifindex); goto out; }
    if (!strcmp(argv[1], "detach")) { rc = s.exists ? remove_instance(&s) : 0; goto out; }
    if (s.complete && s.attached[0] && s.attached[1] && s.config.ifindex == ifindex) {
        if (memcmp(s.config.build, ctfo_build, sizeof(ctfo_build)))
            rc = refuse("a different build is attached; stop the socket and detach it before upgrading");
        else rc = report(&s, interface, port, ifindex);
        goto out;
    }
    if (s.exists && remove_instance(&s)) { rc = -1; goto out; }
    memset(s.id, 0, sizeof(s.id));
    s.complete = false;
    if (create_instance(&s, port, ifindex)) { rc = -1; goto out; }
    if (inspect(&s, port)) { rc = -1; goto out; }
    if (!s.complete || !s.attached[0] || !s.attached[1] || if_nametoindex(interface) != ifindex) {
        rc = refuse("interface disappeared during attachment");
        remove_instance(&s);
        goto out;
    }
    rc = report(&s, interface, port, ifindex);
out:
    close_instance(&s);
    close(lockfd);
    return rc ? 1 : 0;
}
