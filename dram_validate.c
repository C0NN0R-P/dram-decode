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

#define NUM_ACCESSES 5000

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
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
    if (lseek(fd, offset, SEEK_SET) == -1) {
        perror("lseek pagemap");
        exit(EXIT_FAILURE);
    }

    if (read(fd, &value, sizeof(uint64_t)) != sizeof(uint64_t)) {
        perror("read pagemap");
        exit(EXIT_FAILURE);
    }

    close(fd);

    if (!(value & (1ULL << 63))) {
        fprintf(stderr, "Page not present\n");
        exit(EXIT_FAILURE);
    }

    uint64_t frame = value & ((1ULL << 55) - 1);
    return (frame * 4096) | ((uintptr_t)virt & 0xFFF);
}

void access_memory(void *addr) {
    for (int i = 0; i < NUM_ACCESSES; i++) {
        asm volatile("clflush (%0)" :: "r"(addr));
        asm volatile("mfence");
        *(volatile char *)addr;
    }
}

void decode_physical_address(uint64_t pa) {
    system("dmesg -C");

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "insmod skx_dram_decode_addr.ko phys_addr=0x%lx", pa);
    system(cmd);
    sleep(1); // give time for decode output

    FILE *fp = popen("dmesg | grep skx_decode", "r");
    if (!fp) {
        perror("popen");
        return;
    }

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "phys =")) {
            printf("Decode output: %s", line);
            found = 1;
        }
    }
    pclose(fp);

    if (!found) {
        printf("Failed to parse decode output.\n");
    }

    system("rmmod skx_dram_decode_addr");
}

int main(int argc, char **argv) {
    void *target = NULL;
    int num = 0;
    int opt;

    while ((opt = getopt(argc, argv, "a:n:")) != -1) {
        switch (opt) {
            case 'a':
                sscanf(optarg, "%p", &target);
                break;
            case 'n':
                num = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s [-a address] [-n num_addresses]\n", argv[0]);
                return 1;
        }
    }

    if (!target && num == 0) {
        fprintf(stderr, "Specify either -a address or -n num_addresses\n");
        return 1;
    }

    for (int i = 0; i < (num ? num : 1); i++) {
        void *addr = target;

        if (!addr) {
            addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (addr == MAP_FAILED) {
                perror("mmap");
                return 1;
            }
            *((volatile char *)addr) = 1;
        }

        uint64_t pa = virt_to_phys(addr);
        printf("\nVA: %p\n", addr);
        printf("PA: 0x%lx\n", pa);
        printf("Running decode module...\n");

        decode_physical_address(pa);

        struct perf_event_attr pe = {0};
        pe.type = 13;             // PERF_TYPE_RAW
        pe.size = sizeof(struct perf_event_attr);
        pe.config = 0x304;        // uncore_imc_0/cas_count_read/
        pe.disabled = 0;
        pe.exclude_kernel = 0;
        pe.exclude_hv = 0;

        int fd = perf_event_open(&pe, -1, 0, -1, 0);
        if (fd == -1) {
            perror("perf_event_open failed");
            fprintf(stderr, "Failed to set up CAS counter.\n");
            return 1;
        }

        uint64_t before, after;
        read(fd, &before, sizeof(before));
        access_memory(addr);
        read(fd, &after, sizeof(after));
        printf("CAS delta: %llu (Number of accesses: %d)\n\n", (unsigned long long)(after - before), NUM_ACCESSES);
        close(fd);
    }

    return 0;
}
