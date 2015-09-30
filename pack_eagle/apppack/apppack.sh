#!/bin/sh

serial=$1
out=$2

dd if=/dev/zero of=$out bs=1024 count=20480
mkfs.msdos app.img -n $serial 
rm tmp

if [ -d mnt ];then
	mkdir mnt
fi
sudo rm mnt/*

sudo umount mnt
sudo mount app.img mnt
sudo cp -v app/* mnt/
sudo sync
sudo umount mnt

