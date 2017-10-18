/*
 * Interface for attack demo
 * Authors:
 *   Tao Zhang <zhtao@cs.unc.edu>
 */

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/gfp.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/page.h>

#include "dune.h"
#include "attack.h"

static void *demo_addr = NULL;
static struct page *demo_pages = NULL;
static __u64 demo_buf_size = 0;
static int demo_buf_order = 0;

static int set_pages_exe(unsigned long addr, int order)
{
	int count = 1 << order;

	while (count-- > 0) {
		unsigned int level;
		pte_t *pte = lookup_address(addr, &level);

		printk(KERN_DEBUG "%s:%d Trying to change addr %p PTE entry from %lx to %lx\n",
				__FILE__, __LINE__,
				(void *) addr, pte_val(*pte), pte_val(*pte) & ~_PAGE_NX);

		*pte = pte_clear_flags(*pte, _PAGE_NX);
	}

	return 0;
}

static void *get_demo_buf(unsigned long size)
{
	int ret;

	if (size > demo_buf_size) {
		if (demo_addr != NULL) {
			printk(KERN_DEBUG "%s:%d freeing previous pages with size %lu order %d\n",
					__FILE__, __LINE__, (unsigned long) demo_buf_size, demo_buf_order);
			__free_pages(demo_pages, demo_buf_order);
			demo_pages = NULL;
			demo_addr = NULL;
		}

		demo_buf_order = get_order(size);
		demo_buf_size = (1 << demo_buf_order) << PAGE_SHIFT;
		printk(KERN_DEBUG "%s:%d allocating new pages with size %lu order %d\n",
				__FILE__, __LINE__, (unsigned long) demo_buf_size, demo_buf_order);

		demo_pages = alloc_pages(GFP_KERNEL, demo_buf_order);
		if (IS_ERR(demo_pages)) {
			return demo_pages;
		}

		demo_addr = __va((page_to_pfn(demo_pages) << PAGE_SHIFT));

		/* Always set pages as executable */
		ret = set_pages_exe((unsigned long) demo_addr, demo_buf_order);
	}
	return demo_addr;
}


int azk_attack_mem(unsigned long arg)
{
	long r = 0;

	struct azk_attack_mem_config conf;

	r = copy_from_user(&conf, (void __user *) arg,
			sizeof(struct azk_attack_mem_config));
	if (r) {
		printk(KERN_WARNING "%s:%d Failed to obtain attack config from user (%ld)\n",
				__FILE__, __LINE__, r);
		return r;
	}

	/* If target address not set, use our own memory space for demo */
	if (conf.addr == 0) {
		conf.addr = (unsigned long) get_demo_buf(conf.size);

		if (IS_ERR((void *) conf.addr)) {
			printk(KERN_WARNING "%s:%d Failed to get demo buffer space (%ld)\n",
					__FILE__, __LINE__, PTR_ERR((void *) conf.addr));
			return PTR_ERR((void *) conf.addr);
		}
		printk(KERN_DEBUG "%s:%d Using default memory space %p\n",
				__FILE__, __LINE__, (void *) conf.addr);
	}

	switch (conf.op) {
		case OP_MEM_READ:
			r = copy_to_user(conf.buf,
					(void *) conf.addr, conf.size);

			break;
		case OP_MEM_WRITE:
			r = copy_from_user((void *) conf.addr,
					conf.buf, conf.size);
			break;
		default:
			printk(KERN_WARNING "%s:%d Unknown op (%x)\n",
					__FILE__, __LINE__, conf.op);
			return -EINVAL;
	}
	return 0;
}

int azk_attack_exe(unsigned long arg)
{
	int r;
	struct azk_attack_exe_config conf;
	void (*func)(void) = NULL;

	r = copy_from_user(&conf, (void __user *) arg,
			sizeof(struct azk_attack_exe_config));

	if (r) {
		printk(KERN_WARNING "%s:%d Failed to obtain attack config from user (%d)\n",
				__FILE__, __LINE__, r);
		return r;
	}

	if (conf.addr == 0) {
		conf.addr = (unsigned long) demo_addr;

		printk(KERN_DEBUG "%s:%d Using default memory space %p\n",
				__FILE__, __LINE__, (void *) conf.addr);
	}

	printk(KERN_DEBUG "%s:%d Executing target address %p\n",
			__FILE__, __LINE__, (void *) conf.addr);
	func = (void *) conf.addr;

	/* Should first verify that the target address is executable, or will triger page fault */
	func();

	return 0;
}
