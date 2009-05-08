#!/bin/sh

# Make a partitioned filesystem update bundle
# Usage: make-parts build-directory
# The output files are dirname.sha , dirname.img, version.txt
# The build directory name should contain the version number

[ $# != 1 ] \
    && echo "Usage: $0 build-directory" >> /dev/stderr \
    && exit 1

# Ensure we call the binaries that are in the same
# directory as this shell script
MYPATH=$(readlink -f $0)
LIBEXEC=$(dirname $MYPATH)

dir=$1
build=`basename $1`
echo build is $build
hashname=sha256
# hashname=rmd160
outfile=fs.zip

echo 'warning off : write-partition-map write-partition-map " read-partmap" $call-nand  ;' >data.img
echo "data: ${build}.img" >>data.img
echo "partitions:  boot ff  root f00  home -1" >>data.img

echo "set-partition: boot" >>data.img
/usr/sbin/mkfs.jffs2 -n -e128KiB -r ${dir}/boot -o pre.img
/usr/sbin/sumtool -n -p -e 128KiB -i pre.img -o bootfs.img
$LIBEXEC/hashfs $hashname bootfs.img >>data.img

echo "set-partition: root" >>data.img
/usr/sbin/mkfs.jffs2 -n -e128KiB -r ${dir}/root -o pre.img
/usr/sbin/sumtool -n -p -e 128KiB -i pre.img -o rootfs.img
$LIBEXEC/hashfs $hashname rootfs.img >>data.img

echo "set-partition: home" >>data.img
/usr/sbin/mkfs.jffs2 -n -e128KiB -r ${dir}/home -o pre.img
/usr/sbin/sumtool -n -p -e 128KiB -i pre.img -o homefs.img
$LIBEXEC/hashfs $hashname homefs.img >>data.img

cat bootfs.img rootfs.img homefs.img >${build}.img
mv data.img ${build}.sha

echo $build >version.txt

# $LIBEXEC/sig01 sha256 fs data.img >data.sig
# rm -f $outfile
# zip -n .sig:.img:.txt $outfile data.sig version.txt data.img
# rm -f data.tmp data.sig data.img version.txt
