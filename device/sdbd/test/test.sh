#!/bin/sh
sizes="0 1 8 16 32 64 128 256 512 1024 4096 10240 32768 65536 1048576"
gen_test_file() {
	size=$1
	dd if=/dev/urandom of=$size bs=$size count=1 2>/dev/null
}

push ()
{
    rm -rf files
    mkdir files;cd files
    echo "Generic test file in files/"
    for size in $sizes;do
        files="$(($size-2)) $(($size-1)) $size $(($size+1)) $(($size+2))"
        for file in $files;do
            gen_test_file $file
        done
    done
    cd ..

    echo "Pushing ..."
    adb push files /test 2>&1 |grep bytes
}

pull ()
{
    echo "Pulling ..."
    rm -rf pulled
    mkdir pulled
    adb pull /test/ pulled/ 2>&1|grep bytes
}

check()
{
    echo "Checking ..."
    cd files
    md5sum -b * > ../md5
    cd ..

    cd pulled
    md5sum --quiet -c ../md5
    if [ $? -eq 0 ];then
	echo "Test Success"
    fi
    cd ..
}

push
pull
check
