#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <string.h>
#include <errno.h>
#include <x86intrin.h>

#define PAGE_SIZE 4096
#define NUM_ACCESSES 5000

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

uint64_t virt_to_phys(void *vaddr) {
    uint64_t value;
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open pagemap");
        exit(1);
    }
    off_t offset = ((uintptr_t)vaddr >> 9);
    if (lseek(fd, offset, SEEK_SET) == -1) {
        perror("lseek pagemap");
        exit(1);
    }
    if (read(fd, &value, 8) != 8) {
        perror("read pagemap");
        exit(1);
    }
    close(fd);
    if (!(value & (1ULL << 63))) {
        fprintf(stderr, "Page not present\n");
        exit(1);
    }
    uint64_t pfn = value & ((1ULL << 55) - 1);
    return (pfn << 12) | ((uintptr_t)vaddr & 0xFFF);
}

int main() {
    // Step 1: Allocate page
    void *buffer = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
    if (!buffer) {
        perror("alloc");
        return 1;
    }
    memset(buffer, 0, PAGE_SIZE);
    volatile uint64_t *target = (uint64_t *)buffer;

    // Step 2: Virtual to physical
    uint64_t phys = virt_to_phys(target);
    printf("VA: %p\n", target);
    printf("PA: 0x%lx\n", phys);

    // Step 3: Load decode module and print info
    printf("Running decode module...\n");
    system("sudo insmod skx_dram_decode_addr.ko addr=0x0"); // Reset
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "sudo insmod skx_dram_decode_addr.ko addr=0x%lx", phys);
    system(cmd);
    system("sudo rmmod skx_dram_decode_addr");

    // Step 4: Setup CAS counter
    struct perf_event_attr pe = {0};
    pe.type = 13;               // from /sys/.../uncore_imc_0/type
    pe.size = sizeof(pe);
    pe.config = 0x304;          // cas_count_read: event=0x4, umask=0x3
    pe.disabled = 0;
    pe.exclude_kernel = 0;
    pe.exclude_hv = 0;

    int fd = perf_event_open(&pe, -1, 0, -1, 0);
    if (fd == -1) {
        perror("perf_event_open failed");
        fprintf(stderr, "Failed to set up CAS counter.\n");
        return 1;
    }

    // Step 5: Read initial value
    uint64_t before = 0, after = 0;
    read(fd, &before, sizeof(before));

    // Step 6: Access loop
    for (int i = 0; i < NUM_ACCESSES; i++) {
        _mm_clflush(target);  // Evict from cache
        _mm_mfence();
        *target;
    }

    // Step 7: Read final value
    read(fd, &after, sizeof(after));
    close(fd);

    // Step 8: Print CAS delta
    printf("CAS delta: %llu (expected ~%d)\n", (unsigned long long)(after - before), NUM_ACCESSES);

    return 0;
}
