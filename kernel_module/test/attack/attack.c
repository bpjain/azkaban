/* attack.c - Example of an attack to access invalid address. 
 * Authors:
 *   Tao Zhang <zhtao@cs.unc.edu>
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include "dune.h"

/* Try generate a divid error */
void code_div_0(void)
{
	int a = 1/0;

	a = a;
}

/* Try generate a invalid address error */
void code_invalid_addr(void)
{
	int a = * (int *) 0xdeadbeefdeadbeef;

	a = a;
}

int main(int argc, char *argv[])
{
	int ret;
	struct azk_attack_mem_config mem_config;
	struct azk_attack_exe_config exe_config;
	int azk_fd;

	memset(&mem_config, 0, sizeof(mem_config));
	memset(&exe_config, 0, sizeof(exe_config));

	azk_fd = open("/dev/dune", O_RDWR);
	if (azk_fd <= 0) {
		printf("azk: failed to open Azkaban device\n");
		ret = -errno;
		exit(ret);
	}

	mem_config.op = OP_MEM_WRITE;
	mem_config.size = 0x100;
	mem_config.buf = (void *) &code_invalid_addr;
	ret = ioctl(azk_fd, AZK_ATTACK_MEM, &mem_config);
	if (ret < 0) {
		printf("azk: failed to issue ioctl (%d)\n", ret);
		return ret;
	}

	ret = ioctl(azk_fd, AZK_ATTACK_EXE, &exe_config);
	if (ret < 0) {
		printf("azk: failed to issue ioctl (%d)\n", ret);
		return ret;
	}

	return 0;
}

