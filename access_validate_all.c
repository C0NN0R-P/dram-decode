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
#define NUM_ACCESSES 32
#define MAX_RETRIES 5

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int get_uncore_type() {
    FILE *f = fopen("/sys/bus/event_source/devices/uncore_imc_0/type", "r");
    if (!f) return -1;
    int type;
    fscanf(f, "%d", &type);
    fclose(f);
    return type;
}

int setup_uncore_cas_read(int cpu) {
    FILE *f = fopen("/sys/bus/event_source/devices/uncore_imc_0/events/cas_count_read", "r");
    if (!f) return -1;

    char line[128];
    fgets(line, sizeof(line), f);
    fclose(f);

    unsigned long event = 0, umask = 0;
    sscanf(line, "event=0x%lx,umask=0x%lx", &event, &umask);

    int uncore_type = get_uncore_type();
    if (uncore_type < 0) return -1;

    struct perf_event_attr pea = {0};
    pea.type = uncore_type;
    pea.size = sizeof(pea);
    pea.config = (umask << 8) | event;
    pea.disabled = 0;
    pea.exclude_kernel = 0;
    pea.exclude_hv = 0;

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

    if (!(entry & (1ULL << 63))) return 0;  // page not present
    uint64_t pfn = entry & ((1ULL << 55) - 1);
    return (pfn * PAGE_SIZE) + (virtual_addr % PAGE_SIZE);
}

void decode_with_kprobe(uintptr_t pa) {
    char path[] = "/tmp/skx_decode_log.txt";
    char cmd[512];

    snprintf(cmd, sizeof(cmd),
             "sudo insmod skx_dram_decode_addr.ko phys_addr=0x%lx > /dev/null 2>&1; "
             "dmesg | grep skx_decode | tail -n 1 >> %s; "
             "sudo rmmod skx_dram_decode_addr.ko",
             pa, path);
    system(cmd);
}

void print_kprobe_output() {
    FILE *fp = fopen("/tmp/skx_decode_log.txt", "r");
    if (!fp) return;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        printf("→ [KPROBE] %s", line);
    }
    fclose(fp);
    remove("/tmp/skx_decode_log.txt");
}

int main(int argc, char *argv[]) {
    int num = (argc > 1) ? atoi(argv[1]) : NUM_ACCESSES;

    char *buf;
    posix_memalign((void **)&buf, PAGE_SIZE, PAGE_SIZE);
    memset(buf, 0, PAGE_SIZE);

    int cas_fd = setup_uncore_cas_read(0);
    if (cas_fd < 0) {
        perror("CAS counter setup failed");
        return 1;
    }

    printf("%-18s %-18s %-10s %-10s\n", "VA", "PA", "Cycles", "CAS Δ");

    for (int i = 0; i < num; i++) {
        volatile char *ptr = buf + (i * CACHELINE_SIZE);
        uintptr_t va = (uintptr_t)ptr;
        uintptr_t pa = get_physical_address(va);

        uint64_t cas_before = 0, cas_after = 0;
        int retries = 0;
        uint64_t cas_diff = 0, delta_cycles = 0;

        while (retries++ < MAX_RETRIES) {
            _mm_clflush(ptr);
            _mm_mfence();
            usleep(100);  // delay to let eviction happen

            read(cas_fd, &cas_before, sizeof(uint64_t));
            _mm_mfence();

            uint64_t start = __rdtsc();
            volatile char tmp = *ptr;  // access to force DRAM
            uint64_t end = __rdtsc();
            _mm_mfence();

            read(cas_fd, &cas_after, sizeof(uint64_t));

            delta_cycles = end - start;
            cas_diff = (cas_after >= cas_before) ? cas_after - cas_before : 0;
            if (cas_diff > 0) break;
        }

        printf("%-18p 0x%-16lx %-10lu %-10lu\n", (void *)va, pa, delta_cycles, cas_diff);
        decode_with_kprobe(pa);
    }

    print_kprobe_output();
    return 0;
}
