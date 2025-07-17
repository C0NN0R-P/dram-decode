#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>

#define PAGE_SIZE       4096
#define CACHELINE_SIZE  64
#define NUM_ACCESSES    64
#define NUM_TIMINGS     5
#define ROW_HIT_THRESH  200  // You can adjust this based on your platform

// Convert virtual to physical address (requires root)
uint64_t virt_to_phys(void *virt) {
    FILE *pagemap = fopen("/proc/self/pagemap", "rb");
    if (!pagemap) return 0;

    uint64_t value;
    size_t offset = ((uintptr_t)virt >> 12) * sizeof(uint64_t);

    fseek(pagemap, offset, SEEK_SET);
    fread(&value, sizeof(uint64_t), 1, pagemap);
    fclose(pagemap);

    if (!(value & (1ULL << 63))) return 0; // page not present

    uint64_t frame = value & ((1ULL << 55) - 1);
    return (frame << 12) | ((uintptr_t)virt & 0xfff);
}

// Time a single access without cache flush
uint64_t time_access(void *addr) {
    _mm_lfence();
    uint64_t start = __rdtsc();
    *(volatile uint64_t *)addr;
    _mm_lfence();
    return __rdtsc() - start;
}

int main() {
    void *buffer;
    if (posix_memalign(&buffer, PAGE_SIZE, PAGE_SIZE * 2)) {
        perror("posix_memalign");
        return 1;
    }

    memset(buffer, 0, PAGE_SIZE * 2); // Ensure allocation

    printf("VA\t\tPA\t\tCycles[0-4]\t\tResult\n");

    for (int i = 0; i < NUM_ACCESSES; i++) {
        void *addr = (void *)((uintptr_t)buffer + i * CACHELINE_SIZE);
        uint64_t pa = virt_to_phys(addr);
        if (!pa) continue;

        // Flush once
        _mm_clflush(addr);
        _mm_lfence();

        uint64_t cycles[NUM_TIMINGS];
        int hits = 0, misses = 0;

        for (int j = 0; j < NUM_TIMINGS; j++) {
            cycles[j] = time_access(addr);
            if (cycles[j] < ROW_HIT_THRESH)
                hits++;
            else
                misses++;
        }

        printf("%p\t0x%lx\t", addr, pa);
        for (int j = 0; j < NUM_TIMINGS; j++)
            printf("%lu ", cycles[j]);

        if (hits >= 3)
            printf("\tHIT\n");
        else
            printf("\tMISS\n");
    }

    return 0;
}
