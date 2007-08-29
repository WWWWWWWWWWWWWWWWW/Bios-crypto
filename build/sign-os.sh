#!/bin/sh

# Make a signed OS bundle
# Usage: sign-os keyname infile outfile.zip
# Examples:
# sign-os  os  vmlinuz  runos.zip
# sign-os  os  initrd   runrd.zip

[ $# != 3 ] && echo Usage: $0 keyname infile outfile.zip && exit 1

keyname=$1
infile=$2
outfile=$3

./sig01 sha256 $keyname $infile >data.sig
cp $infile data.img
rm -f $outfile
zip -n .sig:.img $outfile data.sig data.img
rm -f data.sig data.img
