/* hello.c - Hello World test case to run a process in the Azkaban mode.
 * Authors:
 *   Bhushan Jain <bhushan@cs.unc.edu>
 *   Tao Zhang <zhtao@cs.unc.edu>
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <unistd.h>
#include <sys/types.h>

#include "dune.h"
//#include "dune2.h"

/*static void recover(void)
{
	printf("hello: recovered from divide by zero\n");
	exit(0);
}

static void divide_by_zero_handler(struct dune_tf *tf)
{
	printf("hello: caught divide by zero!\n");
	tf->rip = (uintptr_t) &recover;
}*/

/*static struct dune_percpu *create_percpu(void)
{
	struct dune_percpu *percpu;
	int ret;
	unsigned long fs_base;

#if 0
	if (arch_prctl(ARCH_GET_FS, &fs_base) == -1) {
		printf("dune: failed to get FS register\n");
		return NULL;
	}
#endif
	percpu = mmap(NULL, PGSIZE, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (percpu == MAP_FAILED)
		return NULL;

	map_ptr(percpu, sizeof(*percpu));

#if 0
        percpu->kfs_base = fs_base;
	percpu->ufs_base = fs_base;
	percpu->in_usermode = 0;

	if ((ret = setup_safe_stack(percpu))) {
		munmap(percpu, PGSIZE);
		return NULL;
	}
#endif
	return percpu;
}
*/
int main(int argc, char *argv[])
{
	volatile int ret, var;
	struct dune_config conf;
	// struct dune_percpu *percpu;

	printf("hello: not running azkaban yet in pid %d\n",getpid());
	// percpu = create_percpu();
	int dune_fd = open("/dev/dune", O_RDWR);
	if (dune_fd <= 0) {
		printf("dune: failed to open Dune device\n");
		ret = -errno;
		exit(ret);
	}

	conf.rip = (__u64) &__dune_ret;
        conf.rsp = 0;
	conf.krsp = 0;
        //conf.cr3 = (physaddr_t) pgroot;
//	printf("Are you sure you want to enter in guest mode?\n");
//        scanf("%d",&var);
//        printf("Doesnt matter. You are gonna enter and fail anyways.\n");

        
        ret = __dune_enter(dune_fd, &conf);
	
	if (ret) {
		printf("azkaban: entry to guest mode failed, ret is %d\n", ret);
		return -EIO;
	}

//	printf("hello: now running in guest mode\n");
	
	//pid_t pid = getpid();

	//scanf("%d",&var);
	
	int abc = 3+5;

	//dune_register_intr_handler(T_DIVIDE, divide_by_zero_handler);

	//ret = 1 / ret; /* divide by zero */

	printf("hello: we won't reach this call\n");

	exit(1);
}

