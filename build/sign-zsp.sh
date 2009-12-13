#!/bin/sh

# Sign a .zsp file into a fs.zip
# Usage: sign-zsp.sh keyname infile
# Example: sign-zsp.sh fs os99.zsp
# Output file is fs.zip

# Ensure we call the binaries that are in the same
# directory as this shell script
MYPATH=$(readlink -f $0)
LIBEXEC=$(dirname $MYPATH)

signingkey=$1
infile=$2
outfile=fs.zip

cp $2 data.img
$LIBEXEC/sig01 sha256 $signingkey data.img > data.sig
rm -f $outfile
zip -n .sig:.img $outfile data.sig data.img
rm -f data.sig data.img

