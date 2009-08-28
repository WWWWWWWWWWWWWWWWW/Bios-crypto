#!/bin/bash

# Make a lease file with an absolute expiry time
# Expiry time must be in the usual format e.g. 20090428T205521Z
# Usage: make-lease.sh serial-number uuid expiry [outfile]
# Example:
# make-lease.sh SHF706002A7 8BF9AC40-26F8-4BCC-A699-BE51FD366419 1 [outfile]

[ $# -lt 3 ] && echo Usage: $0 serial-number uuid expiry [outfile] && exit 1

sn=$1
uu=$2
expiry=$3

if [ $# -ge 4 ]; then
  outfile=$4
else
  outfile=/dev/stdout
fi

if [[ ${#expiry} != 16 || "${expiry:8:1}" != "T" || "${expiry:15:1}" != "Z" ]]; then
	echo "unrecognised date format" >> /dev/stderr
	exit 1
fi

echo act01: $sn K $expiry `echo -n $sn:$uu:K:$expiry | ./sig01 sha256 lease` >$outfile
