/* Header file for Azkaban
 * Authors:
 *   Bhushan Jain <bhushan@cs.unc.edu>
 *   Tao Zhang <zhtao@cs.unc.edu>
 */

#ifndef __AZKABAN_H
#define __AZKABAN_H

#include <asm/percon.h>

#define AZK_MAX_VCPUS	256

#define AZK_HC_EXIT_VM	1
#define AZK_HC_PRINT	2
#define AZK_HC_SCHEDULE 3
#define AZK_HC_ALLOC_PAGES 4
#define AZK_HC_FREE_PAGES 5
#define AZK_HC_PRINT_C_D	10
#define AZK_HC_PRINTK	11

struct azk_config {
	__u64 rip;
	__u64 rsp;
	__u64 cr3;
	__u64 krip;
	__u64 krsp;
	__s64 ret;

	struct vmx_vcpu *vcpus[AZK_MAX_VCPUS];
	//struct mutex lock;
	void *percon_page;
};

static inline int in_azkaban(void) {
	return ((PERCON(azk_flags) & AZK_FL_GUEST_MASK) != 0);
}

#endif
