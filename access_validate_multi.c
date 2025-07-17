#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <x86intrin.h>

#define PAGE_SIZE 4096
#define NUM_ACCESSES 5000
#define ADDR_COUNT 5

// Translate VA -> PA
uint64_t virt_to_phys(void *vaddr) {
    uint64_t value;
    int pagemap = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap < 0) return 0;

    uint64_t offset = ((uintptr_t)vaddr / PAGE_SIZE) * 8;
    if (lseek(pagemap, offset, SEEK_SET) < 0) return 0;
    if (read(pagemap, &value, 8) != 8) return 0;
    close(pagemap);

    if (!(value & (1ULL << 63))) return 0; // page not present

    uint64_t pfn = value & ((1ULL << 55) - 1);
    return (pfn * PAGE_SIZE) + ((uintptr_t)vaddr % PAGE_SIZE);
}

// Decode PA -> DRAM geometry
int decode_with_kprobe(uint64_t pa, int *channel, int *rank, int *bank, int *bg) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "sudo insmod skx_dram_decode_addr.ko phys_addr=0x%lx > /dev/null 2>&1", pa);
    system(cmd);

    FILE *f = fopen("/dev/kmsg", "r");
    if (!f) return -1;

    char line[1024];
    int success = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "[skx_decode]")) {
            if (sscanf(line, "%*[^=]=> socket=0 imc=0 channel=%d dimm=0 rank=%d row=%*x col=%*x bank=%d bg=%d",
                       channel, rank, bank, bg) == 4) {
                success = 1;
                break;
            }
        }
    }
    fclose(f);
    system("sudo rmmod skx_dram_decode_addr.ko");
    return success ? 0 : -1;
}

// Setup uncore event
int setup_cas_counter(int channel, int rank, int bank, int bg) {
    FILE *f = fopen("/sys/bus/event_source/devices/uncore_imc_0/type", "r");
    if (!f) return -1;

    int type;
    fscanf(f, "%d", &type);
    fclose(f);

    uint64_t config = 0x04 | ((uint64_t)rank << 14) | ((uint64_t)bg << 12) |
                      ((uint64_t)bank << 8) | ((uint64_t)channel << 6);

    struct perf_event_attr pea = {
        .type = type,
        .size = sizeof(struct perf_event_attr),
        .config = config,
        .disabled = 1,
        .exclude_kernel = 0,
        .exclude_hv = 1
    };

    return syscall(__NR_perf_event_open, &pea, -1, 0, -1, 0);
}

// Repeated access
void hammer(void *addr) {
    for (int i = 0; i < NUM_ACCESSES; i++) {
        _mm_clflush(addr);
        _mm_mfence();
        *(volatile char *)addr;
        _mm_mfence();
    }
}

int main() {
    void *addrs[ADDR_COUNT];
    for (int i = 0; i < ADDR_COUNT; i++) {
        addrs[i] = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
        memset(addrs[i], 0, PAGE_SIZE);
    }

    printf("VA\t\t\tPA\t\tCAS delta\n");

    for (int i = 0; i < ADDR_COUNT; i++) {
        void *va = addrs[i];
        uint64_t pa = virt_to_phys(va);
        if (!pa) {
            printf("Failed to translate VA %p\n", va);
            continue;
        }

        int ch, rk, bk, bg;
        if (decode_with_kprobe(pa, &ch, &rk, &bk, &bg) != 0) {
            printf("Kprobe decode failed for PA 0x%lx\n", pa);
            continue;
        }

        int fd = setup_cas_counter(ch, rk, bk, bg);
        if (fd < 0) {
            perror("perf_event_open");
            continue;
        }

        uint64_t before = 0, after = 0;
        read(fd, &before, sizeof(before));
        hammer(va);
        read(fd, &after, sizeof(after));
        close(fd);

        printf("%p\t0x%lx\t%lu\n", va, pa, after - before);
    }

    return 0;
}
