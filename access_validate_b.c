#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int read_sysfs_int(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    int val;
    if (fscanf(fp, "%d", &val) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return val;
}

uint64_t read_event_config(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    char buf[256];
    uint64_t config = 0;
    while (fgets(buf, sizeof(buf), fp)) {
        char *event_str = strstr(buf, "event=");
        char *umask_str = strstr(buf, "umask=");
        if (event_str && umask_str) {
            unsigned long event = strtoul(event_str + 6, NULL, 0);
            unsigned long umask = strtoul(umask_str + 6, NULL, 0);
            config = (umask << 8) | event;
            break;
        }
    }
    fclose(fp);
    return config;
}

int main() {
    int type = read_sysfs_int("/sys/bus/event_source/devices/uncore_imc_0/type");
    if (type == -1) {
        fprintf(stderr, "Failed to read event type\n");
        return 1;
    }

    uint64_t config = read_event_config("/sys/bus/event_source/devices/uncore_imc_0/events/cas_count_read");
    if (config == 0) {
        fprintf(stderr, "Failed to read event config\n");
        return 1;
    }

    struct perf_event_attr pea;
    memset(&pea, 0, sizeof(pea));
    pea.type = (uint32_t)type;
    pea.size = sizeof(struct perf_event_attr);
    pea.config = config;
    pea.disabled = 0;
    pea.inherit = 1;
    pea.exclude_kernel = 0;
    pea.exclude_hv = 0;
    pea.exclude_idle = 0;
    pea.read_format = 0;

    // Try with system-wide monitoring
    int fd = perf_event_open(&pea, 0, -1, -1, 0);
    if (fd == -1) {
        perror("perf_event_open failed");
        return 1;
    }

    uint64_t before = 0, after = 0;
    if (read(fd, &before, sizeof(before)) != sizeof(before)) {
        perror("Failed to read counter before");
        close(fd);
        return 1;
    }

    printf("Sleeping 1 second...\n");
    sleep(1);

    if (read(fd, &after, sizeof(after)) != sizeof(after)) {
        perror("Failed to read counter after");
        close(fd);
        return 1;
    }

    printf("CAS count delta: %llu\n", (unsigned long long)(after - before));
    close(fd);
    return 0;
}
