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
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#define NUM_ACCESSES 5000
#define MAX_RANKS 8
#define MAX_BANKS 16
#define MAX_BANKGROUPS 4
#define DELTA_THRESHOLD 3000
#define HUGE_ALLOC_SIZE (8L * 1024 * 1024 * 1024) // 8GB
#define STRIDE_SIZE (1 * 128) 

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
        asm volatile("clflush (%0)\n\t" : : "r" (addr));
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
    } else if (strcmp(label, "BankGroup") == 0) {
        *event = 0xB0 + rank;
        *umask = 0x10 + (bank + 1); // bank is treated as bankgroup here
    } else {
        *event = 0;
        *umask = 0;
    }
    return ((uint64_t)(*umask) << 8) | *event;
}

void run_kernel_decode(uint64_t pa, int *channel, int *rank, int *bank, int *bg, int kprobe_rank_hits[MAX_RANKS], int kprobe_bank_hits[MAX_RANKS][MAX_BANKS], int kprobe_bg_hits[MAX_RANKS][MAX_BANKGROUPS]) {
    char command[512];
    char buffer[512];
    int calculated_bank = 0;
    FILE *fp;

    system("sudo dmesg -C");

    snprintf(command, sizeof(command),
             "sudo insmod skx_dram_decode_addr.ko phys_addr=0x%llx > /dev/null 2>&1; sudo rmmod skx_dram_decode_addr.ko",
             (unsigned long long)pa);
    system(command);

    fp = popen("dmesg", "r");
    if (!fp) {
        perror("popen failed");
        exit(EXIT_FAILURE);
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if (strstr(buffer, "skx_decode")) {
            if (strstr(buffer, "Loading skx_dram_decode_addr module") || strstr(buffer, "skx_dram_decode_addr module unloaded")) {
                continue;
            }
            printf("%s", buffer);
            if (sscanf(buffer,
                       "[%*[^]]] [skx_decode] phys = %*s => socket=%*d imc=%*d channel=%d dimm=%*d rank=%d row=%*x col=%*x bank=%d bg=%d",
                       channel, rank, bank, bg) == 4) {
                if (*rank >= 0 && *rank < MAX_RANKS) {
                    kprobe_rank_hits[*rank]++;
                }
                if (*rank >= 0 && *rank < MAX_RANKS && *bank >= 0 && *bank < MAX_BANKS) {
                    kprobe_bank_hits[*rank][*bank]++;
                }
                if (*rank >= 0 && *rank < MAX_RANKS && *bg >= 0 && *bg < MAX_BANKGROUPS) {
                    kprobe_bg_hits[*rank][*bg]++;
                }
                if (*rank >= 0 && *rank < MAX_RANKS && *bank >= 0 && *bank < MAX_BANKS && *bg >= 0 && *bg < MAX_BANKGROUPS) {
                    calculated_bank = (*bank * 4) + *bg;
                }
                // printf("Calculated bank = %d\n", calculated_bank);
            }
        }
    }
    pclose(fp);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <number_of_addresses>\n", argv[0]);
        return 1;
    }

    int num_pages = atoi(argv[1]);
    if (num_pages <= 0) {
        fprintf(stderr, "Invalid number of addresses (must be greater than 0)\n");
        return 1;
    }

    srand(time(NULL));

    void *huge_block = mmap(NULL, HUGE_ALLOC_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (huge_block == MAP_FAILED) {
        perror("mmap huge block");
        return 1;
    }

    int rank_hits[MAX_RANKS] = {0};
    int bank_hits[MAX_RANKS][MAX_BANKS] = {0};
    int bankgroup_hits[MAX_RANKS][MAX_BANKGROUPS] = {0};
    int kprobe_rank_hits[MAX_RANKS] = {0};
    int kprobe_bank_hits[MAX_RANKS][MAX_BANKS] = {0};
    int kprobe_bg_hits[MAX_RANKS][MAX_BANKGROUPS] = {0};

    for (int i = 0; i < num_pages; i++) {
        uintptr_t random_offset = ((uintptr_t)rand() << 16) ^ rand();
        random_offset = (random_offset % (HUGE_ALLOC_SIZE / STRIDE_SIZE)) * STRIDE_SIZE;
        void *addr = (void *)((uintptr_t)huge_block + random_offset);
        *((volatile char *)addr) = 1;

        uint64_t phys_addr = virt_to_phys(addr);
        printf("\nVA: %p\n", addr);
        printf("PA: 0x%llx\n", (unsigned long long)phys_addr);

        int channel, rank, bank, bg;
        run_kernel_decode(phys_addr, &channel, &rank, &bank, &bg, kprobe_rank_hits, kprobe_bank_hits, kprobe_bg_hits);
        for (int pmu_type = 13; pmu_type <=18; pmu_type++) {

            Result best_rank = {0}, best_bank = {0}, best_bankgroup = {0};

            for (int rank_idx = 0; rank_idx < MAX_RANKS; rank_idx++) {
                int umask = 0, event = 0;
                uint64_t delta;
                uint64_t config = get_config("Rank", rank_idx, 0, &umask, &event);
                delta = read_perf_event(pmu_type, config, addr, "Rank", umask, event, &delta);
                if (delta >= DELTA_THRESHOLD) {
                    // printf("Delta (Rank, event 0x%X, umask 0x%X): %llu => Rank = %d, PMU type = %d\n", event, umask, (unsigned long long)delta, rank_idx, pmu_type);
                    rank_hits[rank_idx]++;
                }
                if (delta > best_rank.delta) {
                    best_rank = (Result){"Rank", event, umask, delta};
                }
            }

            for (int rank_idx = 0; rank_idx < MAX_RANKS; rank_idx++) {
                for (int bank_idx = 0; bank_idx < MAX_BANKS; bank_idx++) {
                    int umask = 0, event = 0;
                    uint64_t delta;
                    uint64_t config = get_config("Bank", rank_idx, bank_idx, &umask, &event);
                    delta = read_perf_event(pmu_type, config, addr, "Bank", umask, event, &delta);
                    if (delta >= DELTA_THRESHOLD) {
                        // printf("Delta (Bank, event 0x%X, umask 0x%X): %llu => Rank = %d, Bank = %d, PMU type = %d\n", event, umask, (unsigned long long)delta, rank_idx, umask, pmu_type);
                        bank_hits[rank_idx][bank_idx]++;
                    }
                    if (delta > best_bank.delta) {
                        best_bank = (Result){"Bank", event, umask, delta};
                    }
                }
            }

            for (int rank_idx = 0; rank_idx < MAX_RANKS; rank_idx++) {
                for (int bg_idx = 0; bg_idx < 4; bg_idx++) {
                    int umask = 0, event = 0;
                    uint64_t config = get_config("BankGroup", rank_idx, bg_idx, &umask, &event);
                    uint64_t delta = read_perf_event(pmu_type, config, addr, "BankGroup", umask, event, &delta);
                    if (delta >= DELTA_THRESHOLD) {
                        // printf("Delta (BankGroup, event 0x%X, umask 0x%X): %llu => Rank = %d, Bank Group = %d, PMU type = %d\n", event, umask, (unsigned long long)delta, rank_idx, bg_idx, pmu_type);
                        bankgroup_hits[rank_idx][bg_idx]++;
                    }
                    if (delta > best_bankgroup.delta) {
                        best_bankgroup = (Result){"BankGroup", event, umask, delta};
                    }
                }
            }

            if (best_rank.delta >= DELTA_THRESHOLD || best_bank.delta >= DELTA_THRESHOLD || best_bankgroup.delta >= DELTA_THRESHOLD) {
               // printf("Best Rank: Delta %llu (event 0x%X, umask 0x%X) => Rank = %d\n", (unsigned long long)best_rank.delta, best_rank.event, best_rank.umask, best_rank.event - 0xB0);
               // printf("Best Bank: Delta %llu (event 0x%X, umask 0x%X) => Bank = %d\n", (unsigned long long)best_bank.delta, best_bank.event, best_bank.umask, best_bank.umask);
               // printf("Best BankGroup: Delta %llu (event 0x%X, umask 0x%X) => Bank Group = %d\n", (unsigned long long)best_bankgroup.delta, best_bankgroup.event, best_bankgroup.umask, best_bankgroup.umask - 0x10 - 1);
		printf("PMU type = %d Rank = %d Bank = %d BankGroup = %d\n", pmu_type, best_rank.event - 0xB0, best_bank.umask, best_bankgroup.umask - 0x10 - 1);
            }
        }
    }

    munmap(huge_block, HUGE_ALLOC_SIZE);
    return 0;
}
