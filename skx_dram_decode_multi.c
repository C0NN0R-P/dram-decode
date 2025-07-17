#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Connor Pfreundschuh");
MODULE_DESCRIPTION("Batch decode physical addresses using skx_edac");

#define MAX_ADDRS 128

struct skx_dev;

struct decoded_addr {
    struct skx_dev *dev;
    u64 addr;
    int socket;
    int imc;
    int channel;
    u64 chan_addr;
    int sktways;
    int chanways;
    int dimm;
    int rank;
    int channel_rank;
    u64 rank_address;
    int row;
    int column;
    int bank_address;
    int bank_group;
};

// Accept an array of physical addresses via module parameter
static u64 phys_addrs[MAX_ADDRS];
static int num_phys_addrs;
module_param_array(phys_addrs, ullong, &num_phys_addrs, 0644);
MODULE_PARM_DESC(phys_addrs, "Array of physical addresses to decode");

typedef bool (*skx_decode_t)(struct decoded_addr *);
static skx_decode_t real_skx_decode = NULL;

static struct kprobe kp = {
    .symbol_name = "skx_decode",
};

static int __init skx_decode_multi_init(void) {
    struct decoded_addr res;

    pr_info("[skx_decode_multi] Loading module...\n");

    // Register kprobe to resolve skx_decode
    if (register_kprobe(&kp)) {
        pr_err("[skx_decode_multi] Failed to register kprobe on skx_decode\n");
        return -ENOSYS;
    }

    real_skx_decode = (skx_decode_t)kp.addr;
    unregister_kprobe(&kp);

    if (!real_skx_decode) {
        pr_err("[skx_decode_multi] Failed to resolve skx_decode address\n");
        return -ENOSYS;
    }

    if (num_phys_addrs == 0) {
        pr_err("[skx_decode_multi] No physical addresses specified (use phys_addrs=...)\n");
        return -EINVAL;
    }

    int i;
    for (i = 0; i < num_phys_addrs; i++) {
        memset(&res, 0, sizeof(res));
        res.addr = phys_addrs[i];

        if (real_skx_decode(&res)) {
            pr_info("[skx_decode_multi] phys = 0x%llx => socket=%d imc=%d channel=%d dimm=%d rank=%d row=0x%x col=0x%x bank=%d bg=%d\n",
                (unsigned long long)res.addr,
                res.socket, res.imc, res.channel,
                res.dimm, res.rank, res.row, res.column,
                res.bank_address, res.bank_group);
        } else {
            pr_err("[skx_decode_multi] Failed to decode physical address 0x%llx\n",
                (unsigned long long)res.addr);
        }
    }

    return 0;
}

static void __exit skx_decode_multi_exit(void) {
    pr_info("[skx_decode_multi] Module unloaded.\n");
}

module_init(skx_decode_multi_init);
module_exit(skx_decode_multi_exit);
