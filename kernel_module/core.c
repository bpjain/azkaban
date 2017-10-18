/**
 * core.c - the Azkaban core
 *
 *
 * FIXME: Currently only Intel VMX is supported.
 *
 * Authors:
 *   Bhushan Jain <bhushan@cs.unc.edu>
 *   Tao Zhang <zhtao@cs.unc.edu>
 *
 * This is an extenstion of dune's implementation for hardware virtualization.
 * Original Authors:
 *   Adam Belay <abelay@stanford.edu>
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/compat.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/azkaban.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <asm/kvm_para.h>
#include <asm/percon.h>
#include "dune.h"
#include "vmx.h"

#include "attack.h"

DEFINE_PERCON(struct dune_config, test_config);

DEFINE_PERCON(uint64_t, azk_flags);
DEFINE_PERCON(struct task_struct *, azk_init_task);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A driver for Dune");

static int __init dune_init(void);
static void __exit dune_exit(void);


static int dune_enter(struct azk_config *conf, int64_t *ret)
{
	dump_stack();
	return vmx_launch(conf, ret);
}

static long dune_dev_ioctl(struct file *filp,
			  unsigned int ioctl, unsigned long arg)
{
	__label__ out;
	long r = -EINVAL;
	struct azk_config *conf;
	struct dune_layout layout;
	struct dune_config *test = &test_config;
	uint64_t *pazk_flag = &azk_flags;
	struct dune_config dune_config;

	conf = kzalloc(sizeof(struct azk_config), GFP_KERNEL);

	printk(KERN_ERR "\n Dune enter value is 0x%04x. And the address of test_config is 0x%16lx.\n Percon begin is 0x%16lx. Percon end is 0x%16lx. The size is 0x%4x.\n", DUNE_ENTER, test, &__percon_beginning, &__percon_end, &__percon_end - &__percon_beginning);

	azk_flags = 0;

	switch (ioctl) {
	case DUNE_ENTER:
		r = copy_from_user(&dune_config, (int __user *) arg,
				   sizeof(struct dune_config));
		if (r) {
			r = -EIO;
			goto out;
		}

		conf->rip = dune_config.rip;
		conf->rsp = dune_config.rsp;
		conf->cr3 = dune_config.cr3;
		conf->krip = dune_config.krip;
		conf->krsp = dune_config.krsp;
		conf->ret = dune_config.ret;

		conf->krip = (unsigned long)&&out;
		asm("mov %%rsp, %0": "=r"(conf->krsp));
		r = dune_enter(conf, &conf->ret);
		if (r)
			break;

/*		r = copy_to_user((void __user *)arg, &conf,
				 sizeof(struct dune_config));
		if (r) {
			r = -EIO;
			goto out;
		}
*/
//		r = 0;
		break;

	case DUNE_GET_SYSCALL:
		rdmsrl(MSR_LSTAR, r);
		printk(KERN_INFO "R %lx\n", (unsigned long) r);
		break;

	case DUNE_GET_LAYOUT:
		layout.base_proc = 0;
		layout.base_map = LG_ALIGN(current->mm->mmap_base) - GPA_SIZE;
		layout.base_stack = ((unsigned long) current->mm->context.vdso & ~GPA_MASK);
		r = copy_to_user((void __user *)arg, &layout,
				 sizeof(struct dune_layout));
		if (r) {
			r = -EIO;
			goto out;
		}
		break;

	case AZK_ATTACK_MEM:
		r = azk_attack_mem(arg);
		break;

	case AZK_ATTACK_EXE:
		r = azk_attack_exe(arg);
		break;

	default:
		return -ENOTTY;
	}


	barrier();

out:
//	kvm_hypercall1(2,r);
	return r;
}

static const struct file_operations dune_chardev_ops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= dune_dev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= dune_dev_ioctl,
#endif
	.llseek		= noop_llseek,
};

static struct miscdevice dune_dev = {
	DUNE_MINOR,
	"dune",
	&dune_chardev_ops,
};

static int __init dune_init(void)
{
	int r;

	printk(KERN_ERR "Dune module loading\n");

	if ((r = vmx_init())) {
		printk(KERN_ERR "dune: failed to initialize vmx\n");
		return r;
	}

	r = misc_register(&dune_dev);
	if (r) {
		printk(KERN_ERR "dune: misc device register failed\n");
		vmx_exit();
	}

	printk(KERN_ERR "Dune module loaded\n");

	return r;
}

static void __exit dune_exit(void)
{
	misc_deregister(&dune_dev);
	vmx_exit();
}

module_init(dune_init);
module_exit(dune_exit);
