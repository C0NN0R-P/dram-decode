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
#define NUM_ACCESSES 100000

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

uintptr_t get_physical_address(uintptr_t virtual_addr) {
    FILE *pagemap = fopen("/proc/self/pagemap", "rb");
    if (!pagemap) return 0;

    uint64_t offset = (virtual_addr / PAGE_SIZE) * sizeof(uint64_t);
    fseek(pagemap, offset, SEEK_SET);

    uint64_t entry;
    if (fread(&entry, sizeof(uint64_t), 1, pagemap) != 1) {
        fclose(pagemap);
        return 0;
    }
    fclose(pagemap);

    if (!(entry & (1ULL << 63))) return 0;

    uint64_t pfn = entry & ((1ULL << 55) - 1);
    return (pfn * PAGE_SIZE) + (virtual_addr % PAGE_SIZE);
}

int decode_with_kprobe(uint64_t pa, int *channel, int *rank, int *bank, int *bg) {
    char cmd[512], buf[1024];
    FILE *fp;

    snprintf(cmd, sizeof(cmd),
             "sudo insmod skx_dram_decode_addr.ko phys_addr=0x%lx > /dev/null 2>&1; "
             "dmesg | tail -n 20 | grep skx_decode; "
             "sudo rmmod skx_dram_decode_addr.ko", pa);

    fp = popen(cmd, "r");
    if (!fp) return -1;

    int found = 0;
    while (fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, "[skx_decode]") && strstr(buf, "phys =")) {
            if (sscanf(buf,
                       "%*[^=]=> socket=0 imc=0 channel=%d dimm=0 rank=%d row=%*x col=%*x bank=%d bg=%d",
                       channel, rank, bank, bg) == 4) {
                found = 1;
                break;
            }
        }
    }

    pclose(fp);
    return found ? 0 : -1;
}

int get_uncore_type() {
    FILE *f = fopen("/sys/bus/event_source/devices/uncore_imc_0/type", "r");
    if (!f) return -1;
    int type;
    if (fscanf(f, "%d", &type) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return type;
}

int setup_cas_counter(int ch, int rk, int bk, int bg) {
    int uncore_type = get_uncore_type();
    if (uncore_type < 0) return -1;

    struct perf_event_attr pea = {0};
    pea.type = uncore_type;
    pea.size = sizeof(struct perf_event_attr);
    pea.config = (0x01 << 8) | 0x04;  // umask=0x01, event=0x04 for CAS read
    pea.disabled = 0;
    pea.exclude_kernel = 0;
    pea.exclude_hv = 0;

    return perf_event_open(&pea, -1, 0, -1, 0);  // CPU 0 for simplicity
}

void hammer(void *addr) {
    for (int i = 0; i < NUM_ACCESSES; i++) {
        _mm_clflush(addr);
        _mm_mfence();
        *(volatile char *)addr;
        _mm_mfence();
    }
}

int main(int argc, char *argv[]) {
    int num_addrs = 20;
    if (argc > 1) num_addrs = atoi(argv[1]);

    char *region;
    if (posix_memalign((void **)&region, PAGE_SIZE, PAGE_SIZE * 2) != 0) {
        perror("alloc");
        return 1;
    }
    memset(region, 0, PAGE_SIZE * 2);

    printf("VA                  PA                  CAS delta  ch rk bk bg\n");

    for (int i = 0; i < num_addrs; i++) {
        volatile char *ptr = region + (i * CACHELINE_SIZE);
        uintptr_t va = (uintptr_t)ptr;
        uintptr_t pa = get_physical_address(va);
        if (!pa) continue;

        int ch = -1, rk = -1, bk = -1, bg = -1;
        if (decode_with_kprobe(pa, &ch, &rk, &bk, &bg) != 0) {
            printf("Failed to decode PA 0x%lx\n", pa);
            continue;
        }

        int fd = setup_cas_counter(ch, rk, bk, bg);
        if (fd < 0) {
            printf("Failed to setup CAS counter\n");
            continue;
        }

        uint64_t before = 0, after = 0;
        if (read(fd, &before, sizeof(before)) != sizeof(before)) {
            perror("read before");
            close(fd);
            continue;
        }

        hammer((void *)ptr);

        if (read(fd, &after, sizeof(after)) != sizeof(after)) {
            perror("read after");
            close(fd);
            continue;
        }

        close(fd);
        printf("0x%016lx  0x%016lx  %10lu  %2d %2d %2d %2d\n",
               va, pa, after - before, ch, rk, bk, bg);
    }

    return 0;
}
