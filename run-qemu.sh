#!/bin/bash

while [ "$#" -gt 0 ]; do

if [[ "$1" = "-gdb" || "$2" = "-gdb" ]]; then
	GDB="-s"
fi

if [[ "$1" = "-serial" || "$2" = "-serial" ]]; then
	SERIAL_APPEND="console=\"ttyS0,115200\""
	SERIAL="-serial file:console.log.$(date "+%Y.%m.%d-%H.%M.%S")"
fi

shift
done

CONSOLE="console=tty1 highres=off $SERIAL_APPEND"
ROOT="root=/dev/hda rw --no-log"
NCPUS=`grep -c ^processor /proc/cpuinfo`

set -x

qemu-system-x86_64 $GDB -enable-kvm -cpu host,+vmx -m 2048M -smp $NCPUS -hda disk.img -kernel arch/x86/boot/bzImage \
	-initrd initrd.img \
	-append "$CONSOLE $ROOT" \
	-curses -snapshot $SERIAL
