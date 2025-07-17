#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <x86intrin.h>

#define PAGE_SIZE       4096
#define CACHELINE_SIZE  64
#define NUM_ACCESSES    64
#define NUM_TIMINGS     5
#define ROW_HIT_THRESH  200

// Convert VA to PA
uint64_t virt_to_phys(void *virt) {
    FILE *pagemap = fopen("/proc/self/pagemap", "rb");
    if (!pagemap) return 0;

    uint64_t value;
    size_t offset = ((uintptr_t)virt >> 12) * sizeof(uint64_t);

    fseek(pagemap, offset, SEEK_SET);
    fread(&value, sizeof(uint64_t), 1, pagemap);
    fclose(pagemap);

    if (!(value & (1ULL << 63))) return 0; // Not present

    uint64_t frame = value & ((1ULL << 55) - 1);
    return (frame << 12) | ((uintptr_t)virt & 0xfff);
}

// Time access without clflush
uint64_t time_access(void *addr) {
    _mm_lfence();
    uint64_t start = __rdtsc();
    *(volatile uint64_t *)addr;
    _mm_lfence();
    return __rdtsc() - start;
}

// Run skx_dram_decode on a physical address and get decode string
void decode_physical(uint64_t pa, char *result, size_t size) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "echo %lx > /sys/module/skx_dram_decode_addr/parameters/phys_addr", pa);
    system(cmd); // trigger the decode

    FILE *fp = popen("dmesg | grep skx_decode | tail -n 1", "r");
    if (fp) {
        fgets(result, size, fp);
        pclose(fp);
    } else {
        snprintf(result, size, "decode error");
    }
}

int main() {
    void *buffer;
    if (posix_memalign(&buffer, PAGE_SIZE, PAGE_SIZE * 2)) {
        perror("posix_memalign");
        return 1;
    }

    memset(buffer, 0, PAGE_SIZE * 2);

    printf("VA\t\tPA\t\tResult\t\t\tLatency[0-4]\t\tClassification\n");

    for (int i = 0; i < NUM_ACCESSES; i++) {
        void *addr = (void *)((uintptr_t)buffer + i * CACHELINE_SIZE);
        uint64_t pa = virt_to_phys(addr);
        if (!pa) continue;

        _mm_clflush(addr);
        _mm_lfence();

        uint64_t latencies[NUM_TIMINGS];
        int hits = 0, misses = 0;

        for (int j = 0; j < NUM_TIMINGS; j++) {
            latencies[j] = time_access(addr);
            if (latencies[j] < ROW_HIT_THRESH)
                hits++;
            else
                misses++;
        }

        char decode_result[256] = {0};
        decode_physical(pa, decode_result, sizeof(decode_result));

        printf("%p\t0x%lx\t", addr, pa);
        printf("%.*s\t", (int)(strchr(decode_result, '\n') - decode_result), decode_result);

        for (int j = 0; j < NUM_TIMINGS; j++)
            printf("%lu ", latencies[j]);

        printf("\t%s\n", (hits >= 3) ? "HIT" : "MISS");
    }

    return 0;
}
