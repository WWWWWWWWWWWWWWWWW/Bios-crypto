#!/bin/sh

# Make a signed firmware bundle
# Usage: sign-fw keyname infile outfile.zip
# Examples:
# sign-fw  fw  q2c25.rom bootfw.zip

[ $# != 3 ] && echo Usage: $0 keyname infile outfile.zip && exit 1

keyname=$1
infile=$2
outfile=$3

./sig01 sha256 $keyname $infile >data.sig
./sig01 rmd160 $keyname $infile >>data.sig
cp $infile data.img
rm -f $outfile
zip -n .sig:.img $outfile data.sig data.img
rm -f data.sig data.img
