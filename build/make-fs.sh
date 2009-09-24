#!/bin/sh

# Make a filesystem update bundle
# Usage: make-fs input-filename
# Example:
# make-fs  os612.img
# The output file is fs.zip

[ $# != 1 ] && echo Usage: $0 osname && exit 1

infile=$1
buildname=`basename $infile .img`
hashname=sha256
# hashname=rmd160
outfile=fs.zip


echo "data: " `basename $infile` >data.img
./hashfs $hashname $infile data.tmp
cat data.tmp >>data.img

echo $buildname >version.txt

./sig01 sha256 fs data.img >data.sig
rm -f $outfile
zip -n .sig:.img:.txt $outfile data.sig version.txt data.img
rm -f data.tmp data.sig data.img version.txt
