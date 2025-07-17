#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <errno.h>
#include <x86intrin.h>
#include <time.h>

#define PAGE_SIZE 4096
#define CACHELINE_SIZE 64
#define NUM_ACCESSES 100000

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int get_uncore_type() {
    FILE *f = fopen("/sys/bus/event_source/devices/uncore_imc_0/type", "r");
    if (!f) {
        perror("Failed to open uncore type");
        return -1;
    }
    int type;
    if (fscanf(f, "%d", &type) != 1) {
        perror("Failed to read uncore type");
        fclose(f);
        return -1;
    }
    fclose(f);
    return type;
}

int setup_uncore_cas_read(int cpu) {
    FILE *f = fopen("/sys/bus/event_source/devices/uncore_imc_0/events/cas_count_read", "r");
    if (!f) {
        perror("Failed to read event definition");
        return -1;
    }

    char line[128];
    if (!fgets(line, sizeof(line), f)) {
        perror("Failed to read event line");
        fclose(f);
        return -1;
    }
    fclose(f);

    unsigned long event = 0, umask = 0;
    if (sscanf(line, "event=0x%lx,umask=0x%lx", &event, &umask) != 2) {
        fprintf(stderr, "Failed to parse event string: %s\n", line);
        return -1;
    }

    int uncore_type = get_uncore_type();
    if (uncore_type < 0) return -1;

    struct perf_event_attr pea = {0};
    pea.type = uncore_type;
    pea.size = sizeof(struct perf_event_attr);
    pea.config = (umask << 8) | event;
    pea.disabled = 0;
    pea.exclude_kernel = 0;
    pea.exclude_hv = 0;
    pea.read_format = 0;

    int fd = perf_event_open(&pea, -1, cpu, -1, 0);
    if (fd == -1) {
        perror("perf_event_open failed");
        printf("type = %d, config = 0x%llx, cpu = %d\n", pea.type, (unsigned long long)pea.config, cpu);
    }
    return fd;
}

uintptr_t get_physical_address(uintptr_t virtual_addr) {
    FILE *pagemap = fopen("/proc/self/pagemap", "rb");
    if (!pagemap) return 0;

    uint64_t offset = (virtual_addr / PAGE_SIZE) * sizeof(uint64_t);
    fseek(pagemap, offset, SEEK_SET);

    uint64_t entry;
    if (fread(&entry, sizeof(uint64_t), 1, pagemap) != 1) {
        fclose(pagemap);
        return 0;
    }
    fclose(pagemap);

    if (!(entry & (1ULL << 63))) return 0;

    uint64_t pfn = entry & ((1ULL << 55) - 1);
    return (pfn * PAGE_SIZE) + (virtual_addr % PAGE_SIZE);
}

int main(int argc, char *argv[]) {
    int num_accesses = 10;
    if (argc > 1) {
        num_accesses = atoi(argv[1]);
        if (num_accesses <= 0) {
            fprintf(stderr, "Invalid num_accesses: %s\n", argv[1]);
            return 1;
        }
    }

    char *buf;
    if (posix_memalign((void **)&buf, PAGE_SIZE, PAGE_SIZE * 2) != 0) {
        perror("posix_memalign failed");
        return 1;
    }
    memset(buf, 0, PAGE_SIZE * 2);

    printf("%-18s %-18s %-10s %-8s %-10s\n", "VA", "PA", "Cycles", "Hit/Miss", "CAS Δ");

    int cas_fd = setup_uncore_cas_read(0);
    if (cas_fd < 0) {
        fprintf(stderr, "Failed to setup CAS counter\n");
    }

    for (int i = 0; i < num_accesses; i++) {
        volatile char *ptr = buf + (i * CACHELINE_SIZE);
        _mm_clflush((const void *)ptr);
        _mm_mfence();

        uint64_t cas_before = 0, cas_after = 0;
        if (cas_fd >= 0) read(cas_fd, &cas_before, sizeof(uint64_t));

        uint64_t start = __rdtsc();
        *ptr;
        uint64_t end = __rdtsc();
        _mm_mfence();

        if (cas_fd >= 0) read(cas_fd, &cas_after, sizeof(uint64_t));

        uintptr_t va = (uintptr_t)ptr;
        uintptr_t pa = get_physical_address(va);
        int diff = end - start;
        uint64_t cas_diff = (cas_after >= cas_before) ? (cas_after - cas_before) : 0;

        const char *status = diff < 100 ? "HIT" : "MISS";
        printf("%-18p 0x%-16lx %-10d %-8s %-10lu\n", (void *)va, pa, diff, status, cas_diff);
    }

    return 0;
}
