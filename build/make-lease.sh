#!/bin/sh

# Make a lease file
# Usage: make-lease.sh serial-number uuid [days|expire] [outfile]
# Example:
# make-lease.sh SHF706002A7 8BF9AC40-26F8-4BCC-A699-BE51FD366419 1 [outfile]

[ $# -lt 3 ] && echo Usage: $0 serial-number uuid [days|expire] [outfile] && exit 1

sn=$1
uu=$2
expire=$3

if [ $# -ge 4 ]; then
  outfile=$4
else
  outfile=/dev/stdout
fi

if [[ ${#expire} != 16 || "${expire:8:1}" != "T" || "${expire:15:1}" != "Z" ]]; then
    expire=`./futureday.py $expire`
    if [ $? != 0 ]; then
	echo "unrecognised date format" >> /dev/stderr
	exit 1
    fi
fi

echo act01: $sn K $expire `echo -n $sn:$uu:K:$expire | ./sig01 sha256 lease` >$outfile
