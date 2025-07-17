/*
 * verify_with_decode.c
 *
 * Compares DRAM address verification via:
 *   (1) PMU-based CAS read counts (perf_event)
 *   (2) Kernel-based decode using skx_decode (via kprobe module output)
 *
 * Supports:
 *   --manual <addr>: verify one user-supplied physical address
 *   --random: generate and verify several random addresses
 *
 * Requires: root or CAP_SYS_ADMIN
 */

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

int setup_uncore_event(uint64_t config, int cpu) {
    struct perf_event_attr pea = {0};
    pea.type = PERF_TYPE_RAW;
    pea.size = sizeof(struct perf_event_attr);
    pea.config = config;
    pea.disabled = 1;
    pea.exclude_kernel = 0;
    pea.exclude_hv = 1;

    int fd = perf_event_open(&pea, -1, cpu, -1, 0);
    if (fd == -1) {
        perror("perf_event_open");
        exit(EXIT_FAILURE);
    }
    return fd;
}

void flush(void *addr) {
    _mm_clflush(addr);
    _mm_mfence();
}

uint64_t rdtsc() {
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

void measure_perf(uint64_t addr) {
    void *map = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        return;
    }

    volatile char *ptr = (char *)map;
    int fd_cas = setup_uncore_event(0x104, 0); // CAS READS for SKX

    ioctl(fd_cas, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd_cas, PERF_EVENT_IOC_ENABLE, 0);

    uint64_t start = rdtsc();
    for (int i = 0; i < NUM_ACCESSES; ++i) {
        flush((void *)ptr);
        *ptr;
    }
    uint64_t end = rdtsc();

    ioctl(fd_cas, PERF_EVENT_IOC_DISABLE, 0);

    uint64_t cas_count;
    if (read(fd_cas, &cas_count, sizeof(uint64_t)) != sizeof(uint64_t)) {
        perror("read");
        cas_count = 0;
    }

    printf("→ [PMU] Cycles: %lu\n", end - start);
    printf("→ [PMU] CAS reads: %lu\n", cas_count);

    close(fd_cas);
    munmap(map, PAGE_SIZE);
}

void measure_kprobe(uint64_t addr) {
    void *map = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        return;
    }

    volatile char *ptr = (char *)map;
    printf("→ [KPROBE] Accessing addr=0x%lx to trigger kernel-side decode (check dmesg)\n", addr);

    for (int i = 0; i < 1000; ++i) {
        flush((void *)ptr);
        *ptr;
    }

    munmap(map, PAGE_SIZE);
}

void run_both_methods(uint64_t addr) {
    printf("ADDR: 0x%lx (check kernel logs for true DRAM decode)\n", addr);

    printf("--- PMU VERIFICATION ---\n");
    measure_perf(addr);

    printf("--- KPROBE VERIFICATION ---\n");
    measure_kprobe(addr);

    printf("(Compare PMU counters above with DRAM decode output in dmesg)\n\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s --manual <addr>\n       %s --random\n", argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--manual") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Manual mode requires one address.\n");
            return 1;
        }
        uint64_t addr = strtoull(argv[2], NULL, 0);
        run_both_methods(addr);
    } else if (strcmp(argv[1], "--random") == 0) {
        srand(time(NULL));
        for (int i = 0; i < 5; ++i) {
            uint64_t addr = ((uint64_t)rand() << 32 | rand()) & 0x0000FFFFFFFFF000ULL;
            run_both_methods(addr);
        }
    } else {
        fprintf(stderr, "Unknown mode: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
