/* A kernel module that uses kprobes to hook skx_decode from skx_edac
 */

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
MODULE_DESCRIPTION("DRAM decoder using skx_edac via kprobes");

/* Forward declaration of struct (should match skx_edac.c) */
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

typedef bool (*skx_decode_t)(struct decoded_addr *);
skx_decode_t real_skx_decode = NULL;

static struct kprobe kp = {
	.symbol_name = "skx_decode",
};

static int __init skx_real_decode_init(void) {
	void *test_page;
	phys_addr_t phys;
	struct decoded_addr res;

	pr_info("[skx_decode] Module loading, installing kprobe...\n");

	if (register_kprobe(&kp)) {
		pr_err("[skx_decode] Failed to register kprobe on skx_decode\n");
		return -ENOSYS;
	}

	real_skx_decode = (skx_decode_t)kp.addr;
	unregister_kprobe(&kp);

	if (!real_skx_decode) {
		pr_err("[skx_decode] Failed to resolve skx_decode\n");
		return -ENOSYS;
	}

	test_page = (void *)__get_free_page(GFP_KERNEL);
	if (!test_page) {
		pr_err("[skx_decode] Failed to allocate page\n");
		return -ENOMEM;
	}

	memset(test_page, 0xAB, PAGE_SIZE);
	phys = virt_to_phys(test_page);
	memset(&res, 0, sizeof(res));
	res.addr = phys;

	if (real_skx_decode(&res)) {
		pr_info("[skx_decode] phys=0x%llx => socket=%d imc=%d channel=%d dimm=%d rank=%d row=0x%x col=0x%x bank=%d bg=%d\n",
			(unsigned long long)res.addr,
			res.socket, res.imc, res.channel,
			res.dimm, res.rank, res.row, res.column,
			res.bank_address, res.bank_group);
	} else {
		pr_err("[skx_decode] Failed to decode physical address\n");
	}

	free_page((unsigned long)test_page);
	return 0;
}

static void __exit skx_real_decode_exit(void) {
	pr_info("[skx_decode] Module unloaded.\n");
}

module_init(skx_real_decode_init);
module_exit(skx_real_decode_exit);
