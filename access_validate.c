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

#define PAGE_SIZE 4096
#define CACHELINE_SIZE 64
#define NUM_ACCESSES 5000

// --- Set this manually based on decoded physical address ---
#define CHANNEL 0
#define RANK    1
#define BANK    2
#define BKG     3

// Read physical address using /proc/self/pagemap
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

    uint64_t pfn = entry & ((1ULL << 55) - 1);
    return (pfn * PAGE_SIZE) + (virtual_addr % PAGE_SIZE);
}

// Get event source type for uncore_imc
int get_uncore_type() {
    FILE *f = fopen("/sys/bus/event_source/devices/uncore_imc_0/type", "r");
    if (!f) return -1;

    int type;
    fscanf(f, "%d", &type);
    fclose(f);
    return type;
}

// Setup CAS read counter on correct channel/imc
int setup_cas_counter(int cpu) {
    FILE *f = fopen("/sys/bus/event_source/devices/uncore_imc_0/events/cas_count_read", "r");
    if (!f) return -1;

    char line[128];
    fgets(line, sizeof(line), f);
    fclose(f);

    unsigned long event = 0, umask = 0;
    if (sscanf(line, "event=0x%lx,umask=0x%lx", &event, &umask) != 2)
        return -1;

    int type = get_uncore_type();
    if (type < 0) return -1;

    struct perf_event_attr pea = {0};
    pea.type = type;
    pea.size = sizeof(pea);
    pea.config = (umask << 8) | event;
    pea.disabled = 0;
    pea.exclude_kernel = 0;
    pea.exclude_hv = 0;
    pea.read_format = 0;

    return syscall(__NR_perf_event_open, &pea, -1, cpu, -1, 0);
}

// Flush cache line
void clflush(volatile void *p) {
    asm volatile("clflush (%0)" :: "r"(p));
    asm volatile("mfence");
}

// --- Main ---
int main() {
    char *buf;
    posix_memalign((void **)&buf, PAGE_SIZE, PAGE_SIZE);
    memset(buf, 0, PAGE_SIZE);

    volatile char *target = buf + 128;  // Arbitrary offset
    uintptr_t va = (uintptr_t)target;
    uintptr_t pa = get_physical_address(va);

    printf("VA: 0x%lx --> PA: 0x%lx\n", va, pa);
    printf("Channel: %d Rank: %d Bank: %d BKG: %d\n", CHANNEL, RANK, BANK, BKG);

    int fd = setup_cas_counter(0);
    if (fd < 0) {
        perror("Failed to set up CAS counter");
        return 1;
    }

    uint64_t before = 0, after = 0;
    read(fd, &before, sizeof(uint64_t));

    for (int i = 0; i < NUM_ACCESSES; i++) {
        clflush((void *)target);
        *target;
    }

    read(fd, &after, sizeof(uint64_t));
    close(fd);

    printf("CAS delta = %lu (should be ~%d)\n", after - before, NUM_ACCESSES);

    return 0;
}
