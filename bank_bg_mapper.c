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
#define MAX_BANKS 16
#define MAX_BANKGROUPS 4
#define DELTA_THRESHOLD 500
#define HUGE_ALLOC_SIZE (8L * 1024 * 1024 * 1024) // 8GB
#define STRIDE_SIZE (1 * 512)

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

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

uint64_t read_perf_event(uint64_t config, void *addr) {
    struct perf_event_attr pe = {0};
    pe.type = PERF_TYPE_RAW;
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

    uint64_t before = 0, after = 0;
    read(fd, &before, sizeof(before));
    access_memory(addr);
    read(fd, &after, sizeof(after));
    close(fd);

    return after - before;
}

uint64_t get_config(int rank, int bg) {
    int event = 0xB0 + rank;
    int umask = 0x10 + (bg + 1);
    return ((uint64_t)umask << 8) | event;
}

void run_kernel_decode(uint64_t pa, int *channel, int *rank, int *bank, int *bg) {
    char command[512], buffer[512];
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
        if (strstr(buffer, "skx_decode") &&
            !strstr(buffer, "Loading") && !strstr(buffer, "unloaded")) {
            sscanf(buffer,
                   "[%*[^]]] [skx_decode] phys = %*s => socket=%*d imc=%*d channel=%d dimm=%*d rank=%d row=%*x col=%*x bank=%d bg=%d",
                   channel, rank, bank, bg);
            break;
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
        fprintf(stderr, "Invalid number of addresses\n");
        return 1;
    }

    srand(time(NULL));

    void *huge_block = mmap(NULL, HUGE_ALLOC_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (huge_block == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    int bankgroup_hits[MAX_BANKS][MAX_BANKGROUPS] = {0};
    int edac_banks_seen[MAX_BANKS] = {0};
    int edac_bgs_seen[MAX_BANKGROUPS] = {0};

    for (int i = 0; i < num_pages; i++) {
        uintptr_t random_offset = ((uint64_t)rand() << 32 | rand()) % (HUGE_ALLOC_SIZE / STRIDE_SIZE);
        random_offset *= STRIDE_SIZE;
        void *addr = (void *)((uintptr_t)huge_block + random_offset);
        *((volatile char *)addr) = 1;

        uint64_t phys_addr = virt_to_phys(addr);

        int channel = -1, rank = -1, bank = -1, bg = -1;
        run_kernel_decode(phys_addr, &channel, &rank, &bank, &bg);

        if (rank >= 0 && bank >= 0 && bg >= 0) {
            uint64_t config = get_config(rank, bg);
            uint64_t delta = read_perf_event(config, addr);
            if (delta >= DELTA_THRESHOLD) {
                bankgroup_hits[bank][bg]++;
                edac_banks_seen[bank] = 1;
                edac_bgs_seen[bg] = 1;
            }
        }
    }

    printf("\n--- EMPIRICAL BANK TO BANK GROUP DELTA MAPPING ---\n");
    for (int b = 0; b < MAX_BANKS; b++) {
        for (int g = 0; g < MAX_BANKGROUPS; g++) {
            if (bankgroup_hits[b][g] > 0) {
                printf("Bank %d -> BG%d = %d hits\n", b, g, bankgroup_hits[b][g]);
            }
        }
    }

    printf("\n--- EDAC BANKS OBSERVED ---\n");
    for (int b = 0; b < MAX_BANKS; b++) {
        if (edac_banks_seen[b]) {
            printf("Bank %d\n", b);
        }
    }

    printf("\n--- EDAC BANK GROUPS OBSERVED ---\n");
    for (int g = 0; g < MAX_BANKGROUPS; g++) {
        if (edac_bgs_seen[g]) {
            printf("Bank Group %d\n", g);
        }
    }

    munmap(huge_block, HUGE_ALLOC_SIZE);
    return 0;
}
