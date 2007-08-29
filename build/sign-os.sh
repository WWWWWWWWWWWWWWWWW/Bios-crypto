#!/bin/sh

# Make a signed OS bundle
# Usage: sign-os keyname infile outfile
# Examples:
# sign-os  olpc_os_key  vmlinuz  runos.zip
# sign-os  olpc_os_key  initrd   runrd.zip

[ $# != 3 ] && echo Usage: $0 keyname infile outfile && exit 1

keyname=$1
infile=$2
outfile=$3

./sig01 sha256 $keyname $infile >data.sig
cp $infile data.img
rm -f $outfile
zip -n .sig:.img $outfile data.sig data.img
