#!/bin/sh

# Make a developer key
# Usage: make-devkey.sh serial-number uuid [outfile]
# Example:
# make-devkey.sh SHF706002A7 8BF9AC40-26F8-4BCC-A699-BE51FD366419

# Ensure we call the binaries that are in the same
# directory as this shell script
MYPATH=$(command -v $0 | xargs readlink -f )
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

[ $# -lt 2 ] \
    && echo "Usage: $0 [--signingkey keyname] serial-number uuid [outfile]" >> /dev/stderr \
    && exit 1

sn=$1
uu=$2
if [ $# -ge 3 ]; then
  outfile=$3
else
  outfile=/dev/stdout
fi

echo dev01: $sn A 00000000T000000Z `echo -n $sn:$uu:A:00000000T000000Z | $LIBEXEC/sig01 sha256 $signingkey` >$outfile
