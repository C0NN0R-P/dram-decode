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
//#define NUM_ACCESSES 40

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

// Dummy physical address resolution (replace with pagemap method)
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

int main(int argc, char *argv[]) {
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

    //printf("VA\t\t\t\tPA\t\t\t\tCycles\t\tHit/Miss\n");
    printf("%-18s  %-18s  %-10s  %s\n", "VA", "PA", "Cycles", "Hit/Miss");
   
    for (int i = 0; i < num_accesses; i++) {
        volatile char *ptr = buf + (i * CACHELINE_SIZE);
        _mm_clflush((const void *)ptr); // ensure it's a miss

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
        //printf("0x%lx\t0x%lx\t%d\t\t%s\n", va, pa, diff, status);
    	printf("%-18p  0x%-16lx  %-10d  %-4s\n", (void *)va, pa, diff, status);
    }

    // Build module command
    char mod_cmd[4096] = "sudo insmod skx_dram_decode_multi.ko phys_addrs=";
    for (int i = 0; i < num_accesses; i++) {
        char addr_buf[32];
        snprintf(addr_buf, sizeof(addr_buf), "0x%lx,", phys_addrs[i]);
        strcat(mod_cmd, addr_buf);
    }
    mod_cmd[strlen(mod_cmd) - 1] = '\0'; // remove trailing comma

    system("sudo rmmod skx_dram_decode_multi 2>/dev/null");
    system("sudo dmesg -C");
    system(mod_cmd);
    system("sudo dmesg | grep skx_decode_multi > decode_results.log");

    printf("\n[+] Decoding complete. See decode_results.log for mapping.\n");

    return 0;
}
