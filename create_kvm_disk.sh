#!/bin/bash

DISK="disk.img"
SIZE="20G"
MNTPNT=`mktemp -d`
OS=`lsb_release -c | awk '{print $2}'`
ARCH="amd64"
KERNEL=`uname -r`
LOCAL_KERNEL=`make kernelversion 2>/dev/null || true`
LOCAL_VERSION=`scripts/setlocalversion 2>/dev/null || true`
USER=oscar
PASS=oscar
TTYS=ttyS0

function fail {
	[ "$M1" = "1" ] && sudo umount $MNTPNT/dev
	[ "$M0" = "1" ] && sudo umount $MNTPNT
	[ "$D0" = "1" ] && rm $DISK
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

run qemu-img create -f raw $DISK $SIZE; D0=1

run mkfs.ext4 -F $DISK

run sudo mkdir -p $MNTPNT
run sudo mount -o loop $DISK $MNTPNT; M0=1

run sudo debootstrap --arch $ARCH $OS $MNTPNT

function copy_files {
	for f in $*
	do
		run sudo cp -r $f $MNTPNT/${f%/*}
	done
}

if [ "$LOCAL_KERNEL" != "" ]; then
	run sudo cp .config $MNTPNT/boot/config-$LOCAL_KERNEL$LOCAL_VERSION
	run sudo mkdir -p $MNTPNT/lib/modules
	run sudo make modules_install INSTALL_MOD_PATH=$MNTPNT
else
	copy_files /boot/vmlinuz-$KERNEL /boot/initrd.img-$KERNEL /boot/config-$KERNEL
	copy_files /lib/modules/$KERNEL
fi

copy_files /etc/passwd /etc/shadow /etc/group /etc/gshadow

run sudo rm -f $MNTPNT/etc/init/tty[2345678].conf
cat > /tmp/setconsole.sh <<EOF
sed "s:/dev/tty\\[1-[2-8]\\]:/dev/tty1:g" $MNTPNT/etc/default/console-setup > $MNTPNT/etc/default/console-setup.new
mv $MNTPNT/etc/default/console-setup.new $MNTPNT/etc/default/console-setup
EOF
run sudo sh /tmp/setconsole.sh
rm /tmp/setconsole.sh

run sudo mkdir -p $MNTPNT/dev
run sudo mount --bind /dev/ $MNTPNT/dev; M1=1

function chroot_run {
	run sudo chroot $MNTPNT $@
}

if [ "$LOCAL_KERNEL" != "" ]; then
	chroot_run mkinitramfs -o /boot/initrd.img-$LOCAL_KERNEL$LOCAL_VERSION $LOCAL_KERNEL$LOCAL_VERSION
	run sudo mv -f $MNTPNT/boot/initrd.img-$LOCAL_KERNEL$LOCAL_VERSION initrd.img
else
	chroot_run mkinitramfs -o /boot/initrd.img-$KERNEL $KERNEL
	run sudo mv -f $MNTPNT/boot/initrd.img-$KERNEL initrd.img
fi

cat > /tmp/adduser.sh <<EOF
adduser $USER --disabled-password --gecos ""
echo "$USER:$PASS" | chpasswd
EOF
sudo mv /tmp/adduser.sh $MNTPNT
chroot_run sh adduser.sh
sudo rm $MNTPNT/adduser.sh
chroot_run apt-get update
chroot_run apt-get install --yes build-essential autoconf

run sudo umount $MNTPNT/dev; M1=0
run sudo umount $MNTPNT; M0=0

run rmdir $MNTPNT; D0=0
