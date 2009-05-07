#!/bin/sh

# Make a delegation file from a master key to a server's pubkey
# Usage: make-delegation.sh [--fullkey] serial-number uuid expire masterkey serverkey
# Example:
# make-delegation.sh SHF706002A7 1 masterkey serverkey [outfile]
# Notes:
#  - If the signing key is not the master key (if it's not in the XOs' mfg data)
#    then you need to pass --fullkey 
#  - The expiry can be in 'days from now' or as an abs timestamp in the format
#    required by the signatures.

[ $# -lt 3 ] && echo Usage: $0 [--fullkey] serial-number [days|expire] masterkey  [outfile] && exit 1

fullkey=""
if [ "$1" == "--fullkey" ];then
    fullkey=" --fullkey "
    shift
fi

sn=$1
expire=$2
mkey=$3
tkey=$4

if [ $# -ge 5 ]; then
  outfile=$5
else
  outfile=/dev/stdout
fi

mkeyhex=`./key01 $mkey.public`
tkeyhex=`./key01 $tkey.public`


if [[ ${#expire} != 16 || "${expire:8:1}" != "T" || "${expire:15:1}" != "Z" ]]; then
    expire=`./futureday.py $expire`
    if [ $? != 0 ]; then
	echo "unrecognised date format" >> /dev/stderr
	exit 1
    fi
fi


echo -n $sn:$expire:$tkeyhex | ./sig01 $fullkey --v2 $expire sha256 $mkey >$outfile
