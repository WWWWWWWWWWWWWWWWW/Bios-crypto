#!/bin/sh

# Make a developer key
# Usage: make-devkey.sh serial-number uuid [outfile]
# Example:
# make-devkey.sh SHF706002A7 8BF9AC40-26F8-4BCC-A699-BE51FD366419

[ $# -lt 2 ] && echo Usage: $0 serial-number uuid [outfile] && exit 1

sn=$1
uu=$2
if [ $# -ge 3 ]; then
  outfile=$3
else
  outfile=/dev/fd/0
fi

echo dev01: $sn A `echo -n $sn:$uu:A:00000000T000000Z | ./sig01 sha256 fw` >$outfile
