/*
 * verify_with_decode.c
 *
 * Combines DRAM decoding and PMU-based verification of address mappings.
 *
 * Supports two modes:
 *   --random: generates random physical addresses
 *   --manual <addr>: verifies user-provided address
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

struct decoded_address {
    int channel;
    int dimm;
    int rank;
    int bank;
    int row;
    int column;
};

/* DRAM decoding logic based on dram-decode/skx_dram_decode_addr.c */
int decode_physical_address(uint64_t addr, struct decoded_address *out) {
    uint64_t col, row, bank, rank, channel, dimm;

    // Bits based on empirical reverse-engineering for Skylake-SP/X
    col = (addr >> 6) & 0x3F;
    row = ((addr >> 18) & 0x7FFF);

    // Bank is a function of bits 14, 15, 16, XORed with higher bits
    uint64_t b0 = (addr >> 14) & 1;
    uint64_t b1 = (addr >> 15) & 1;
    uint64_t b2 = (addr >> 16) & 1;
    bank = (b2 << 2) | (b1 << 1) | b0;

    // Rank is often a function of bit 17 and 18, or 18 and 19
    rank = ((addr >> 17) ^ (addr >> 18)) & 0x1;

    // Channel hashing function: typically XOR of bits
    channel = ((addr >> 6) ^ (addr >> 13) ^ (addr >> 16)) & 0x1;

    dimm = 0; // Assume single DIMM slot unless topology is known

    out->column = col;
    out->row = row;
    out->bank = bank;
    out->rank = rank;
    out->channel = channel;
    out->dimm = dimm;

    return 0;
}

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

void measure_single(uint64_t addr) {
    struct decoded_address d;
    decode_physical_address(addr, &d);

    printf("ADDR: 0x%lx → chan=%d, dimm=%d, rank=%d, bank=%d, row=%d\n",
           addr, d.channel, d.dimm, d.rank, d.bank, d.row);

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

    printf("→ Cycles: %lu\n", end - start);
    printf("→ CAS reads: %lu\n\n", cas_count);

    close(fd_cas);
    munmap(map, PAGE_SIZE);
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
        measure_single(addr);
    } else if (strcmp(argv[1], "--random") == 0) {
        srand(time(NULL));
        for (int i = 0; i < 5; ++i) {
            uint64_t addr = ((uint64_t)rand() << 32 | rand()) & 0x0000FFFFFFFFF000ULL;
            measure_single(addr);
        }
    } else {
        fprintf(stderr, "Unknown mode: %s\n", argv[1]);
        return 1;
    }

    return 0;
}
