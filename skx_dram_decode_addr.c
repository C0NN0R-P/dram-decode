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
MODULE_DESCRIPTION("Decode arbitrary physical address using skx_edac");

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

static u64 phys_addr = 0;
module_param(phys_addr, ullong, 0644);
MODULE_PARM_DESC(phys_addr, "Physical address to decode");

typedef bool (*skx_decode_t)(struct decoded_addr *);
static skx_decode_t real_skx_decode = NULL;

static struct kprobe kp = {
	.symbol_name = "skx_decode",
};

static int __init skx_decode_init(void) {
	struct decoded_addr res;

	pr_info("[skx_decode] Loading skx_dram_decode_addr module...\n");

	if (register_kprobe(&kp)) {
		pr_err("[skx_decode] Failed to register kprobe on skx_decode\n");
		return -ENOSYS;
	}

	real_skx_decode = (skx_decode_t)kp.addr;
	unregister_kprobe(&kp);

	if (!real_skx_decode) {
		pr_err("[skx_decode] Failed to resolve skx_decode address\n");
		return -ENOSYS;
	}

	if (phys_addr == 0) {
		pr_err("[skx_decode] No physical address specified (use phys_addr=0x...)\n");
		return -EINVAL;
	}

	memset(&res, 0, sizeof(res));
	res.addr = phys_addr;

	if (real_skx_decode(&res)) {
		pr_info("[skx_decode] phys = 0x%llx => socket=%d imc=%d channel=%d dimm=%d rank=%d row=0x%x col=0x%x bank=%d bg=%d\n",
			(unsigned long long)res.addr,
			res.socket, res.imc, res.channel,
			res.dimm, res.rank, res.row, res.column,
			res.bank_address, res.bank_group);
	} else {
		pr_err("[skx_decode] Failed to decode physical address 0x%llx\n",
		       (unsigned long long)phys_addr);
	}

	return 0;
}

static void __exit skx_decode_exit(void) {
	pr_info("[skx_decode] skx_dram_decode_addr module unloaded.\n");
}

module_init(skx_decode_init);
module_exit(skx_decode_exit);
