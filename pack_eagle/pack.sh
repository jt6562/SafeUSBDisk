#!/bin/sh
LICHEE_DIR=..

#Create initramfs
if [ ! -e $LICHEE_DIR/out/android/lib/modules/3.0.8/nand.ko ];then
	echo "nand.ko is not exist"
	exit -1
fi
cp -v $LICHEE_DIR/out/android/lib/modules/3.0.8/nand.ko initramfs/lib/modules/
cp -v $LICHEE_DIR/out/android/lib/modules/3.0.8/gpio_sw.ko initramfs/lib/modules/

( cd  initramfs && find . | cpio -o -H newc --quiet | gzip -1 ) > ramdisk.img 
$LICHEE_DIR/tools/pack/pctools/linux/android/mkbootimg --kernel $LICHEE_DIR/out/android/bImage --ramdisk ramdisk.img --base 0x40000000 --output $LICHEE_DIR/out/android/boot.img 

rm -vrf $LICHEE_DIR/tools/pack/out /home/jitao/work/eagle/zrsj/lichee/tools/pack/sun5i_linux_a10s-safedisk-v1.img

#Create hide partition
dd if=/dev/zero of=hidefs.fex bs=32768 count=1024
yes | mkfs.ext4 hidefs.fex
if [ -e tmp ];then
	sudo umount tmp || true
	rm -rfv tmp || true
fi
mkdir tmp
sudo mount hidefs.fex tmp
rm -rf tmp/lost+found
cp -vr hidefs/* tmp
sync
sudo umount -v tmp
rm -r tmp
cp -v hidefs.fex $LICHEE_DIR/out/android/rootfs.ext4

#pack
cd $LICHEE_DIR && ./build.sh pack && cd -

#chown jitao:jitao $LICHEE_DIR/tools/pack/sun5i_linux_a10s-safedisk-v1.img
