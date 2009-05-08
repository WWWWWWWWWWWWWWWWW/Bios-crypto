#!/bin/sh

# Make a filesystem update bundle
# Usage: make-fs input-filename
# Example:
# make-fs  os612.img
# The output file is fs.zip

[ $# != 1 ] && echo Usage: $0 osname && exit 1

# Ensure we call the binaries that are in the same
# directory as this shell script
MYPATH=$(readlink -f $0)
LIBEXEC=$(dirname $MYPATH)

infile="$1"
buildname=`basename "$infile" .img`
hashname=sha256
# hashname=rmd160
outfile=fs.zip

echo "data: " `basename "${infile}"` >data.img
$LIBEXEC/hashfs $hashname "$infile" >>data.img
echo $buildname >version.txt

$LIBEXEC/sig01 sha256 fs data.img >data.sig
rm -f $outfile
zip -n .sig:.img:.txt $outfile data.sig version.txt data.img
rm -f data.sig data.img version.txt
