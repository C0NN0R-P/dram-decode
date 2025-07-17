#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int main() {
    struct perf_event_attr pe = {0};

    // From /sys/bus/event_source/devices/uncore_imc_0/type
    pe.type = 13;

    // From /sys/bus/event_source/devices/uncore_imc_0/events/cas_count_read
    // event=0x04, umask=0x03 → config = 0x304
    pe.size = sizeof(struct perf_event_attr);
    pe.config = 0x304;
    pe.disabled = 0;
    pe.exclude_kernel = 0;
    pe.exclude_hv = 0;

    // Monitor uncore system-wide (cpu = 0, pid = -1)
    int fd = perf_event_open(&pe, -1, 0, -1, 0);
    if (fd == -1) {
        perror("perf_event_open failed");
        return 1;
    }

    uint64_t before = 0, after = 0;
    read(fd, &before, sizeof(before));
    sleep(1);  // You can replace this with memory access if desired
    read(fd, &after, sizeof(after));
    close(fd);

    printf("CAS delta: %llu\n", (unsigned long long)(after - before));
    return 0;
}

