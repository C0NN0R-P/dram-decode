#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/perf_event.h>
#include <getopt.h>
#include <time.h>

#define NUM_ACCESSES 5000
#define MAX_PHYS_BITS 48
#define MAX_ADDRS 65536
#define NUM_PAGES 4096
#define MAX_RANKS 8
#define MAX_BANKS 16
#define DELTA_THRESHOLD 200

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

uint64_t virt_to_phys(void *virt) {
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1) {
        perror("open pagemap");
        exit(EXIT_FAILURE);
    }

    uint64_t value;
    off_t offset = ((uintptr_t)virt / 4096) * sizeof(uint64_t);
    if (lseek(fd, offset, SEEK_SET) == (off_t)-1) {
        perror("lseek pagemap");
        exit(EXIT_FAILURE);
    }

    if (read(fd, &value, sizeof(value)) != sizeof(value)) {
        perror("read pagemap");
        exit(EXIT_FAILURE);
    }

    close(fd);

    if (!(value & (1ULL << 63))) {
        fprintf(stderr, "Page not present\n");
        exit(EXIT_FAILURE);
    }

    uint64_t frame_num = value & ((1ULL << 55) - 1);
    return (frame_num * 4096) | ((uintptr_t)virt & 0xFFF);
}

void access_memory(void *addr) {
    for (int i = 0; i < NUM_ACCESSES; i++) {
        asm volatile("clflushopt (%0)\n\t" : : "r" (addr));
        asm volatile("mfence\n\t");
        *(volatile char *)addr;
    }
}

typedef struct {
    const char *label;
    int event;
    int umask;
    uint64_t delta;
} Result;

uint64_t read_perf_event(int type, uint64_t config, void *addr, const char *label, int umask_val, int event_id, uint64_t *delta_out) {
    struct perf_event_attr pe = {0};
    pe.type = type;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = config;
    pe.disabled = 0;
    pe.exclude_kernel = 0;
    pe.exclude_hv = 0;

    int fd = perf_event_open(&pe, -1, 0, -1, 0);
    if (fd == -1) {
        perror("perf_event_open failed");
        return 0;
    }

    uint64_t before, after;
    (void)read(fd, &before, sizeof(before));
    access_memory(addr);
    (void)read(fd, &after, sizeof(after));
    close(fd);

    uint64_t delta = after - before;
    *delta_out = delta;

    return delta;
}

uint64_t get_config(const char *label, int rank, int bank, int *umask, int *event) {
    if (strcmp(label, "Rank") == 0) {
        *event = 0xB0 + rank;
        *umask = 0x10;
    } else if (strcmp(label, "Bank") == 0) {
        *event = 0xB0 + rank;
        *umask = bank;
    } else {
        *event = 0;
        *umask = 0;
    }
    return ((uint64_t)(*umask) << 8) | *event;
}

void run_kernel_decode(uint64_t pa) {
    char command[512];
    system("sudo dmesg -C");
    snprintf(command, sizeof(command),
             "sudo insmod skx_dram_decode_addr.ko phys_addr=0x%llx > /dev/null 2>&1 && "
             "sudo dmesg | grep skx_decode && "
             "sudo rmmod skx_dram_decode_addr.ko",
             (unsigned long long)pa);
    system(command);
}

int main() {
    size_t page_size = sysconf(_SC_PAGESIZE);
    void *block = mmap(NULL, NUM_PAGES * page_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (block == MAP_FAILED) {
        perror("mmap block");
        return 1;
    }

    for (int i = 0; i < NUM_PAGES; i++) {
        void *addr = (char *)block + i * page_size;
        *((volatile char *)addr) = 1;

        uint64_t phys_addr = virt_to_phys(addr);
        printf("VA: %p\n", addr);
        printf("PA: 0x%llx\n", (unsigned long long)phys_addr);

        run_kernel_decode(phys_addr);

        Result best_rank = {0}, best_bank = {0};

        for (int rank = 0; rank < MAX_RANKS; rank++) {
            int umask = 0, event = 0;
            uint64_t delta;
            uint64_t config = get_config("Rank", rank, 0, &umask, &event);
            delta = read_perf_event(13, config, addr, "Rank", umask, event, &delta);
            if (delta >= DELTA_THRESHOLD) {
                printf("Delta (Rank, event 0x%X, umask 0x%X): %llu => Rank = %d\n",
                       event, umask, (unsigned long long)delta, rank);
            }
            if (delta > best_rank.delta) {
                best_rank = (Result){"Rank", event, umask, delta};
            }
        }

        for (int rank = 0; rank < MAX_RANKS; rank++) {
            for (int bank = 0; bank < MAX_BANKS; bank++) {
                int umask = 0, event = 0;
                uint64_t delta;
                uint64_t config = get_config("Bank", rank, bank, &umask, &event);
                delta = read_perf_event(13, config, addr, "Bank", umask, event, &delta);
                if (delta >= DELTA_THRESHOLD) {
                    printf("Delta (Bank, event 0x%X, umask 0x%X): %llu => Rank = %d, Bank = %d\n",
		           event, umask, (unsigned long long)delta, rank, umask);
                }
                if (delta > best_bank.delta) {
                   best_bank = (Result){"Bank", event, umask, delta};
                }
            }
        }

        printf("Best Rank: Delta %llu (event 0x%X, umask 0x%X) => Rank = %d\n",
               (unsigned long long)best_rank.delta, best_rank.event, best_rank.umask,
               best_rank.event - 0xB0);
        printf("Best Bank: Delta %llu (event 0x%X, umask 0x%X) => Bank = %d\n",
               (unsigned long long)best_bank.delta, best_bank.event, best_bank.umask,
               best_bank.umask);
    }

    munmap(block, NUM_PAGES * page_size);
    return 0;
}
