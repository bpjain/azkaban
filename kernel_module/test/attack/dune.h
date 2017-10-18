/**
 * dune.h - public header for Azkaban support
 * Authors:
 *   Bhushan Jain <bhushan@cs.unc.edu>
 *   Tao Zhang <zhtao@cs.unc.edu>
 *
 * This is an extenstion of dune's public header file.
 * Original Authors:
 *   Adam Belay <abelay@stanford.edu>
 */

#include <linux/types.h>

/*
 * IOCTL interface
 */

/* FIXME: this must be reserved in miscdevice.h */
#define DUNE_MINOR       233

#define DUNE_ENTER	_IOR(DUNE_MINOR, 0x01, struct dune_config)
#define DUNE_GET_SYSCALL	 _IO(DUNE_MINOR, 0x02)
#define DUNE_GET_LAYOUT	_IOW(DUNE_MINOR, 0x03, struct dune_layout)

#define AZK_ATTACK_MEM	_IOW(DUNE_MINOR, 0x04, struct dune_layout)
#define AZK_ATTACK_EXE	_IOW(DUNE_MINOR, 0x05, struct dune_layout)

#define DUNE_HC_EXIT_VM	1
#define DUNE_HC_PRINT	2
#define DUNE_HC_SCHEDULE 3
// XXX: Must match libdune/dune.h
#define DUNE_SIGNAL_INTR_BASE 200

struct dune_config {
	__u64 rip;
	__u64 rsp;
	__u64 cr3;
	__s64 ret;
} __attribute__((packed));

struct dune_layout {
	__u64 base_proc;
	__u64 base_map;
	__u64 base_stack;
} __attribute__((packed));

enum {
	OP_MEM_READ	= 0x00000001,
	OP_MEM_WRITE	= 0x00000002,
	OP_MEM_SET_PF	= 0x00000003,
};
struct azk_attack_mem_config {
	__u64 addr;
	__u8 op;
	__u64 size;
	__u8 *buf;
} __attribute__((packed));

struct azk_attack_exe_config {
	__u64 addr;
} __attribute__((packed));

#define GPA_SIZE ((unsigned long) 1 << 34)
#define GPA_MASK (GPA_SIZE - 1)
#define LG_ALIGN(addr)	((addr + (1 << 21) - 1) & ~((1 << 21) - 1))

enum {
	GPA_ADDR_PROC	= 0x000000000,
	GPA_ADDR_MAP 	= 0x400000000,
	GPA_ADDR_STACK	= 0x800000000,
	GPA_ADDR_INVAL	= 0xC00000000,
};
