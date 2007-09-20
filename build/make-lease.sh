#!/bin/sh

# Make a lease file
# Usage: make-lease.sh serial-number uuid
# Example:
# make-lease.sh SHF706002A7 8BF9AC40-26F8-4BCC-A699-BE51FD366419 1 [outfile]

[ $# -lt 3 ] && echo Usage: $0 serial-number uuid days [outfile] && exit 1

sn=$1
uu=$2
days=$3

if [ $# -ge 4 ]; then
  outfile=$4
else
  outfile=/dev/fd/0
fi

expire=`./futureday.py $days`
echo act01: $sn K $expire `echo -n $sn:$uu:K:$expire | ./sig01 sha256 lease` >$outfile
