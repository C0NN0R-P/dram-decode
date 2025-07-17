#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <errno.h>

#define PAGE_SIZE 4096
#define CACHELINE_SIZE 64
#define NUM_ACCESSES 100

// Get physical address from virtual address using /proc/self/pagemap
uint64_t virt_to_phys(void *vaddr) {
    uint64_t value;
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open pagemap");
        exit(1);
    }

    uint64_t offset = ((uintptr_t)vaddr / PAGE_SIZE) * sizeof(uint64_t);
    if (lseek(fd, offset, SEEK_SET) == (off_t)-1) {
        perror("lseek");
        close(fd);
        exit(1);
    }

    if (read(fd, &value, sizeof(uint64_t)) != sizeof(uint64_t)) {
        perror("read pagemap");
        close(fd);
        exit(1);
    }

    close(fd);

    if (!(value & (1ULL << 63))) {
        fprintf(stderr, "Page not present\n");
        return 0;
    }

    uint64_t pfn = value & ((1ULL << 55) - 1);
    return (pfn * PAGE_SIZE) + ((uintptr_t)vaddr & (PAGE_SIZE - 1));
}

// Accesses and times memory at the given address
uint64_t timed_access(void *addr) {
    _mm_clflush(addr);
    _mm_lfence();
    uint64_t start = __rdtsc();
    *(volatile uint64_t *)addr;
    _mm_lfence();
    uint64_t end = __rdtsc();
    return end - start;
}

int main() {
    void *buffer;
    if (posix_memalign(&buffer, PAGE_SIZE, PAGE_SIZE * 2) != 0) {
        perror("posix_memalign");
        return 1;
    }

    // Touch pages so they get mapped
    memset(buffer, 0, PAGE_SIZE * 2);

    printf("VA\t\tPA\t\tCycles\t\tDecode Result\n");

    for (int i = 0; i < NUM_ACCESSES; i++) {
    void *addr = (void *)((uintptr_t)buffer + (i * CACHELINE_SIZE));
    uint64_t pa = virt_to_phys(addr);
    if (!pa) continue;

    uint64_t cycles = timed_access(addr);

    // Prepare decode command
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "sudo rmmod skx_dram_decode_addr 2>/dev/null; "
        "sudo insmod skx_dram_decode_addr.ko phys_addr=0x%lx > /dev/null 2>&1; "
        "dmesg | tail -n 1 | grep skx_decode",
        pa);

    // Run command and capture output
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        perror("popen");
        continue;
    }

    char result[512] = {0};
    fgets(result, sizeof(result), fp);
    pclose(fp);

    // Print everything nicely
    printf("%p\t0x%lx\t%lu\t%s", addr, pa, cycles, result);
}

    return 0;
}
