#!/bin/sh

# Make a developer key
# Usage: make-devkey.sh serial-number uuid [outfile]
# Example:
# make-devkey.sh SHF706002A7 8BF9AC40-26F8-4BCC-A699-BE51FD366419

[ $# -lt 2 ] && echo Usage: $0 serial-number uuid [outfile] && exit 1

# Ensure we call the binaries that are in the same
# directory as this shell script
MYPATH=$(readlink -f $0)
LIBEXEC=$(dirname $MYPATH)

sn=$1
uu=$2
if [ $# -ge 3 ]; then
  outfile=$3
else
  outfile=/dev/stdout
fi

echo dev01: $sn A 00000000T000000Z `echo -n $sn:$uu:A:00000000T000000Z | $LIBEXEC/sig01 sha256 developer` >$outfile
