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

#define PAGE_SIZE 4096
#define CACHELINE_SIZE 64

#define CAS_READ_EVENT 0x04
#define CAS_UMASK      0x01
#define UNCORE_EVENT_CONFIG ((CAS_UMASK << 8) | CAS_READ_EVENT)

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int setup_uncore_event(uint64_t config, int cpu) {
    struct perf_event_attr pea = {0};
    pea.type = PERF_TYPE_RAW;
    pea.size = sizeof(struct perf_event_attr);
    pea.config = config;
    pea.disabled = 0;
    pea.exclude_kernel = 0;
    pea.exclude_hv = 1;
    pea.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;

    return perf_event_open(&pea, -1, cpu, -1, 0);
}

uintptr_t get_physical_address(uintptr_t virtual_addr) {
    FILE *pagemap = fopen("/proc/self/pagemap", "rb");
    if (!pagemap) return 0;

    uint64_t offset = (virtual_addr / PAGE_SIZE) * sizeof(uint64_t);
    fseek(pagemap, offset, SEEK_SET);
    uint64_t entry;
    fread(&entry, sizeof(uint64_t), 1, pagemap);
    fclose(pagemap);

    if (!(entry & (1ULL << 63))) return 0; // page not present
    uint64_t pfn = entry & ((1ULL << 55) - 1);
    return (pfn * PAGE_SIZE) + (virtual_addr % PAGE_SIZE);
}

int main(int argc, char **argv) {
    int num_accesses = 40;
    if (argc > 1) {
        num_accesses = atoi(argv[1]);
        if (num_accesses <= 0) {
            fprintf(stderr, "Invalid num_accesses: %s\n", argv[1]);
            return 1;
        }
    }

    char *buf;
    posix_memalign((void **)&buf, PAGE_SIZE, PAGE_SIZE * 2);
    memset(buf, 0, PAGE_SIZE * 2);

    uint64_t phys_addrs[num_accesses];
    uintptr_t virt_addrs[num_accesses];
    int cycles[num_accesses];

    int cpu = 0;
    int cas_fd = setup_uncore_event(UNCORE_EVENT_CONFIG, cpu);
    if (cas_fd == -1) {
        perror("perf_event_open failed");
        return 1;
    }

    uint64_t cas_before = 0, cas_after = 0;
    read(cas_fd, &cas_before, sizeof(uint64_t));

    printf("%-18s %-18s %-10s %-8s\n", "VA", "PA", "Cycles", "Hit/Miss");

    for (int i = 0; i < num_accesses; i++) {
        char *ptr = buf + (i * CACHELINE_SIZE);
        _mm_clflush((const void *)ptr);

        _mm_mfence();
        uint64_t start = __rdtsc();
        *ptr;
        uint64_t end = __rdtsc();
        _mm_mfence();

        int diff = end - start;
        uintptr_t va = (uintptr_t)ptr;
        uintptr_t pa = get_physical_address(va);

        phys_addrs[i] = pa;
        virt_addrs[i] = va;
        cycles[i] = diff;

        const char *status = diff < 100 ? "HIT" : "MISS";
        printf("%-18p 0x%-16lx %-10d %-4s\n", (void *)va, pa, diff, status);
    }

    read(cas_fd, &cas_after, sizeof(uint64_t));
    close(cas_fd);

    printf("\n[+] Uncore CAS Reads (IMC%d): %lu \u2192 %lu (\u0394 = %lu)\n",
           cpu, cas_before, cas_after, cas_after - cas_before);

    return 0;
}
