#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <errno.h>

#define PAGE_SIZE 4096

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

uintptr_t get_physical_address(uintptr_t va) {
    FILE *f = fopen("/proc/self/pagemap", "rb");
    if (!f) {
        perror("fopen pagemap");
        return 0;
    }

    uint64_t offset = (va / PAGE_SIZE) * sizeof(uint64_t);
    if (fseek(f, offset, SEEK_SET) != 0) {
        perror("fseek");
        fclose(f);
        return 0;
    }

    uint64_t entry;
    if (fread(&entry, sizeof(entry), 1, f) != 1) {
        perror("fread");
        fclose(f);
        return 0;
    }
    fclose(f);

    if (!(entry & (1ULL << 63))) return 0; // page not present
    return (entry & ((1ULL << 55) - 1)) * PAGE_SIZE + (va % PAGE_SIZE);
}

void decode_dram(uintptr_t pa) {
    char cmd[512];
    const char *log = "/tmp/skx_decode_log.txt";
    remove(log);

    snprintf(cmd, sizeof(cmd),
        "sudo insmod skx_dram_decode_addr.ko phys_addr=0x%lx > /dev/null 2>&1 && "
        "dmesg | tail -n 10 | grep skx_decode > %s && "
        "sudo rmmod skx_dram_decode_addr.ko",
        pa, log);
    system(cmd);

    FILE *fp = fopen(log, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open decode log\n");
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp))
        printf("[DECODE] %s", line);
    fclose(fp);
    remove(log);
}

int setup_cas_counter(void) {
    struct perf_event_attr pe = {0};
    pe.type = 13;                  // From /sys/bus/event_source/devices/uncore_imc_0/type
    pe.size = sizeof(pe);
    pe.config = (0x3 << 8) | 0x4;  // umask=0x3, event=0x4
    pe.disabled = 0;
    pe.exclude_kernel = 0;
    pe.exclude_hv = 0;

    int fd = perf_event_open(&pe, -1, 0, -1, 0); // system-wide, CPU 0
    return fd;
}

int main() {
    char *buf;
    if (posix_memalign((void **)&buf, PAGE_SIZE, PAGE_SIZE)) {
        perror("alloc");
        return 1;
    }
    memset(buf, 0, PAGE_SIZE);

    uintptr_t va = (uintptr_t)buf;
    uintptr_t pa = get_physical_address(va);
    if (!pa) {
        fprintf(stderr, "Physical address not found.\n");
        return 1;
    }

    printf("VA: 0x%lx\n", va);
    printf("PA: 0x%lx\n", pa);

    decode_dram(pa);

    int fd = setup_cas_counter();
    if (fd < 0) {
        perror("perf_event_open failed");
        fprintf(stderr, "Failed to set up CAS counter.\n");
        return 1;
    }

    uint64_t before = 0, after = 0;
    read(fd, &before, sizeof(before));

    for (int i = 0; i < 5000; i++) {
        asm volatile("clflushopt (%0)" :: "r"(buf));
        asm volatile("mfence");
        *(volatile char *)buf;
    }

    read(fd, &after, sizeof(after));
    close(fd);

    printf("CAS delta: %llu (expected ~5000)\n", (unsigned long long)(after - before));
    return 0;
}
