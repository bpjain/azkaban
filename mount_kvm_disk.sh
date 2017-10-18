#!/bin/bash

DISK="disk.img"
MNTPNT=`mktemp -d`
OS=`lsb_release -c | awk '{print $2}'`
ARCH="amd64"
KERNEL=`uname -r`
LOCAL_KERNEL=`make kernelversion 2>/dev/null || true`
USER=oscar
PASS=oscar
TTYS=ttyS0

function fail {
	[ "$M1" = "1" ] && sudo umount $MNTPNT/dev
	[ "$M0" = "1" ] && sudo umount $MNTPNT
	rmdir $MNTPNT
	exit $1
}

function run {
	echo $@
	$@
	if [ $? != 0 ]; then
		echo "Failed [$*]"
		fail $?
	fi
}

run sudo mkdir -p $MNTPNT
run sudo mount -o loop $DISK $MNTPNT; M0=1
run sudo mkdir -p $MNTPNT/dev
run sudo mount --bind /dev/ $MNTPNT/dev; M1=1

function chroot_run {
	run sudo chroot $MNTPNT $@
}

echo "Disk image mounted. Type \"exit\" to unmount the image."

if [ "$1" = "-chroot" ]; then
	chroot_run bash -i
else
	CWD=`pwd`
	cd $MNTPNT && bash -i
	cd $CWD
fi

run sudo umount $MNTPNT/dev; M1=0
run sudo umount $MNTPNT; M0=0

run rmdir $MNTPNT
