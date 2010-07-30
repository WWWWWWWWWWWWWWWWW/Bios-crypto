#!/bin/sh

# Sign a .zsp file into a fs.zip
# Usage: sign-zsp.sh keyname infile
# Example: sign-zsp.sh fs os99.zsp
# Output file is fs.zip

# Ensure we call the binaries that are in the same
# directory as this shell script
MYPATH=$(command -v $0 | xargs readlink -f )
LIBEXEC=$(dirname $MYPATH)

signingkey=$1
infile=$2
outfile=fs.zip

# scripts on OLPC's signing laptop expect fs.zip to contain a version.txt
buildname=$(basename $infile .zsp)
echo $buildname >version.txt

cp $2 data.img
$LIBEXEC/sig01 sha256 $signingkey data.img > data.sig
rm -f $outfile
zip -n .sig:.img:.txt $outfile data.sig data.img version.txt
rm -f data.sig data.img version.txt

