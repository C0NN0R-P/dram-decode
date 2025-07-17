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
#define MAX_ADDRS 4096

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                             int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

uint64_t virt_to_phys(void *virt)
{
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

void access_memory(void *addr)
{
    for (int i = 0; i < NUM_ACCESSES; i++) {
        asm volatile("clflushopt (%0)\n\t" : : "r" (addr));
        asm volatile("mfence\n\t");
        *(volatile char *)addr;
    }
}

int decode_physical_address(uint64_t pa, int *channel, int *rank, int *bank, int *bg)
{
    char modcmd[256];
    snprintf(modcmd, sizeof(modcmd),
             "sudo insmod skx_dram_decode_addr.ko phys_addr=0x%llx > /dev/null 2>&1",
             (unsigned long long)pa);
    system(modcmd);

    FILE *fp = popen("dmesg | grep skx_decode | tail -n 1", "r");
    if (!fp) {
        perror("popen dmesg");
        return -1;
    }

    char line[1024];
    int parsed = 0;
    if (fgets(line, sizeof(line), fp)) {
        fputs(line, stdout);
        int row = -1, col = -1;
        if (sscanf(line,
                   "%*[^=]= 0x%*llx => socket=%*d imc=%*d channel=%d dimm=%*d rank=%d row=0x%x col=0x%x bank=%d bg=%d",
                   channel, rank, &row, &col, bank, bg) == 6) {
            printf("Channel = %d  Rank = %d  Bank = %d  BG = %d\n", *channel, *rank, *bank, *bg);
            parsed = 1;
        } else {
            fprintf(stderr, "Failed to parse decode line.\n");
        }
    }

    pclose(fp);
    system("sudo rmmod skx_dram_decode_addr > /dev/null 2>&1");
    return parsed ? 0 : -1;
}

uint64_t read_perf_event(int type, uint64_t config, void *addr, const char *label, int umask_val, int event_id) {
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

    printf("Delta (%s, event 0x%X, umask 0x%X): %llu\n", label, event_id, umask_val, (unsigned long long)(after - before));
    return after - before;
}

uint64_t get_config(const char *label, int rank, int bank, int bg, int *umask, int *event) {
    if (strcmp(label, "Channel") == 0) {
        *umask = 0x20;
        *event = 0x04;
    } else if (strcmp(label, "Rank") == 0) {
        *umask = 0xB0 + rank;
        *event = 0x10;
    } else if (strcmp(label, "Bank Group") == 0) {
        *umask = 0xB0 + rank;
        *event = 0x11;
    } else if (strcmp(label, "Bank") == 0) {
        *umask = 0xB0 + rank;
        *event = 0x0C;
    } else {
        *umask = 0;
        *event = 0;
    }
    return (*umask << 8) | *event;
}

int main(int argc, char **argv)
{
    void *target = NULL;
    int num = 0;
    int opt;
    int a_provided = 0;

    while ((opt = getopt(argc, argv, "a:n:")) != -1) {
        switch (opt) {
        case 'a':
            sscanf(optarg, "%p", &target);
            a_provided = 1;
            break;
        case 'n':
            num = atoi(optarg);
            break;
        default:
            fprintf(stderr, "Usage: %s [-a address] [-n num_iterations]\n", argv[0]);
            return 1;
        }
    }

    if (!a_provided && num == 0) {
        fprintf(stderr, "Specify either -a address or -n num_iterations\n");
        return 1;
    }

    size_t page_size = sysconf(_SC_PAGESIZE);
    if (!a_provided) {
        srand(time(NULL) ^ getpid());
    }

    int iterations = (num > 0 ? num : 1);
    void *pages[MAX_ADDRS];
    int used = 0;

    for (int i = 0; i < iterations; i++) {
        printf("\nIteration %d\n", i + 1);

        void *addr;
        if (!a_provided) {
            addr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
            if (addr == MAP_FAILED) {
                perror("mmap");
                continue;
            }
            *((volatile char *)addr) = 1;
            pages[used++] = addr;
        } else {
            addr = target;
        }

        uint64_t pa = virt_to_phys(addr);
        printf("VA: %p\n", addr);
        printf("PA: 0x%llx\n", (unsigned long long)pa);
        printf("Running decode module...\n");

        int channel = -1, rank = -1, bank = -1, bg = -1;
        if (decode_physical_address(pa, &channel, &rank, &bank, &bg) != 0) continue;

        const char *labels[] = {"Channel", "Rank", "Bank Group", "Bank"};
        for (int j = 0; j < 4; j++) {
            int umask = 0, event = 0;
            uint64_t config = get_config(labels[j], rank, bank, bg, &umask, &event);
            read_perf_event(13, config, addr, labels[j], umask, event);
        }

        if (!a_provided) munmap(addr, page_size);
    }

    for (int i = 0; i < used; i++) {
        munmap(pages[i], page_size);
    }

    return 0;
}
