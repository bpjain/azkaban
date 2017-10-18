/**
 * dune.h - public header for Azkaban support
 * Authors:
 *   Bhushan Jain <bhushan@cs.unc.edu>
 *   Tao Zhang <zhtao@cs.unc.edu>
 *
 * This is an extenstion of dune's implementation for public header file.
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

// XXX: Must match libdune/dune.h

struct dune_config {
	__u64 rip;
	__u64 rsp;
	__u64 cr3;
	__u64 krip;
	__u64 krsp;
	__s64 ret;
} __attribute__((packed));


//#define LG_ALIGN(addr)	((addr + (1 << 21) - 1) & ~((1 << 21) - 1))

extern int __dune_enter(int fd, struct dune_config *config);
extern int __dune_ret(void);
