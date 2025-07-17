#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/perf_event.h>

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int main() {
    struct perf_event_attr pe = {0};
    pe.type = 13;                           // from /sys/bus/event_source/devices/uncore_imc_0/type
    pe.size = sizeof(struct perf_event_attr);
    pe.config = 0x304;                      // from cas_count_read event=0x4, umask=0x3
    pe.disabled = 0;
    pe.exclude_kernel = 0;
    pe.exclude_hv = 0;

    int fd = perf_event_open(&pe, -1, 0, -1, 0);  // system-wide, uncore counters
    if (fd == -1) {
        perror("perf_event_open failed");
        return 1;
    }

    uint64_t before, after;
    read(fd, &before, sizeof(before));
    sleep(1);
    read(fd, &after, sizeof(after));

    printf("CAS delta: %llu\n", (unsigned long long)(after - before));
    close(fd);
    return 0;
}
