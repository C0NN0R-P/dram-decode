#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <errno.h>
#include <x86intrin.h>

#define PAGE_SIZE 4096
#define CACHELINE_SIZE 64
#define NUM_ACCESSES 5000

// Read physical address from pagemap
uintptr_t get_physical_address(uintptr_t virtual_addr) {
    FILE *f = fopen("/proc/self/pagemap", "rb");
    if (!f) return 0;

    uint64_t offset = (virtual_addr / PAGE_SIZE) * sizeof(uint64_t);
    fseek(f, offset, SEEK_SET);
    uint64_t entry;
    if (fread(&entry, sizeof(uint64_t), 1, f) != 1) {
        fclose(f);
        return 0;
    }
    fclose(f);

    if (!(entry & (1ULL << 63))) return 0;
    return ((entry & ((1ULL << 55) - 1)) * PAGE_SIZE) + (virtual_addr % PAGE_SIZE);
}

// Load and decode via kprobe module
void decode_with_kprobe(uintptr_t pa, char *out_buf, size_t len) {
    system("dmesg -C");
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "sudo insmod skx_dram_decode_addr.ko phys_addr=0x%lx >/dev/null 2>&1", pa);
    system(cmd);
    usleep(50000);
    system("sudo rmmod skx_dram_decode_addr");

    FILE *f = popen("dmesg | grep skx_decode | tail -n 1", "r");
    if (!f) return;
    fgets(out_buf, len, f);
    pclose(f);
}

// Get PMU event type
int get_uncore_type() {
    FILE *f = fopen("/sys/bus/event_source/devices/uncore_imc_0/type", "r");
    if (!f) return -1;
    int t;
    fscanf(f, "%d", &t);
    fclose(f);
    return t;
}

// Set up CAS counter
int setup_cas_counter() {
    FILE *f = fopen("/sys/bus/event_source/devices/uncore_imc_0/events/cas_count_read", "r");
    if (!f) return -1;
    char line[128];
    fgets(line, sizeof(line), f);
    fclose(f);

    unsigned long event, umask;
    if (sscanf(line, "event=0x%lx,umask=0x%lx", &event, &umask) != 2) return -1;

    int type = get_uncore_type();
    if (type < 0) return -1;

    struct perf_event_attr pea = {0};
    pea.type = type;
    pea.size = sizeof(pea);
    pea.config = (umask << 8) | event;
    pea.disabled = 0;
    pea.exclude_kernel = 0;
    pea.exclude_hv = 0;

    return syscall(__NR_perf_event_open, &pea, -1, 0, -1, 0);
}

// Main test
int main(int argc, char *argv[]) {
    int count = (argc > 1) ? atoi(argv[1]) : 1;
    if (count <= 0 || count > 256) {
        fprintf(stderr, "Invalid number of addresses\n");
        return 1;
    }

    char *buf;
    posix_memalign((void **)&buf, PAGE_SIZE, PAGE_SIZE * 2);
    memset(buf, 0, PAGE_SIZE * 2);

    int cas_fd = setup_cas_counter();
    if (cas_fd < 0) {
        perror("CAS counter setup failed");
        return 1;
    }

    printf("%-18s %-18s %-10s %-10s | Decode\n", "VA", "PA", "Cycles", "CAS Δ");

    for (int i = 0; i < count; i++) {
        volatile char *ptr = buf + (i * CACHELINE_SIZE);
        uintptr_t va = (uintptr_t)ptr;
        uintptr_t pa = get_physical_address(va);
        if (!pa) continue;

        _mm_clflush(ptr);
        _mm_mfence();

        uint64_t cas_before = 0, cas_after = 0;
        read(cas_fd, &cas_before, sizeof(uint64_t));

        for (int j = 0; j < NUM_ACCESSES; j++) {
            _mm_clflush(ptr);
            _mm_mfence();
            *ptr;
        }
        _mm_mfence();

        read(cas_fd, &cas_after, sizeof(uint64_t));
        uint64_t delta = (cas_after >= cas_before) ? (cas_after - cas_before) : 0;

        char decode[256] = {0};
        decode_with_kprobe(pa, decode, sizeof(decode));

        printf("%-18p 0x%-16lx %-10d %-10lu | %s",
               (void *)va, pa, NUM_ACCESSES, delta, decode);
    }

    close(cas_fd);
    return 0;
}
