#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "dune.h"

#define AZK_DEV "/dev/dune"

static struct dune_config _azk_conf;

void azk_premain(void) __attribute__ ((constructor (101)));

void azk_premain(void)
{
	int azk_fd;
	int rval;

	printf("[AZK] Executing Azkaban intialization code.\n");

	azk_fd = open(AZK_DEV, O_RDWR);
	if (azk_fd < 0) {
		printf("[AZK] failed to open Azkaban device (%d)\n", azk_fd);
		_exit(azk_fd);
	}

	_azk_conf.rip = (__u64) &__dune_ret;
	_azk_conf.rsp = 0;

	rval = __dune_enter(azk_fd, &_azk_conf);
	if (rval) {
		printf("[AZK] failed to enter Azkaban (%d)\n", rval);
		_exit(rval);
	}
}
