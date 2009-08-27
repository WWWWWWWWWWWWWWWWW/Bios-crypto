#!/bin/sh

# Make developer keys from a CSV file
# Usage: make-devkey-from-csv.sh file.csv
# Example:
# make-devkey-from-csv.sh file.csv

# Ensure we call the binaries that are in the same
# directory as this shell script
MYPATH=$(readlink -f $0)
LIBEXEC=$(dirname $MYPATH)

signingkey="developer"

while [ $# != 0 ] && [ ${1:0:1} == '-' ]; do
    case "$1" in
	--signingkey)
	    signingkey=$2
	    shift;
	    ;;
	*)
	    echo "Unknown param $1" >> /dev/stderr
	    exit 1;
    esac
    shift
done

[ $# -lt 1 ] \
    && echo "Usage: $0 [--signingkey keyname] file.csv [outfile]" >> /dev/stderr \
    && exit 1

FILE=$1

for LINE in `cat "$FILE"`; do
    SN=`echo "$LINE"|cut -d, -f1`
    UUID=`echo "$LINE"|cut -d, -f2`
    "$LIBEXEC"/make-devkey.sh --signingkey $signingkey $SN $UUID
done
