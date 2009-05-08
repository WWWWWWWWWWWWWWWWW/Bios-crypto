#!/bin/sh

# Make a delegation file from a master key to a server's pubkey
# Usage: make-delegation.sh [--fullkey] serial-number uuid expire signingkey targetkey
# Example:
# make-delegation.sh SHF706002A7 1 masterkey serverkey [outfile]
# Notes:
#  - If the signing key is not the master key (if it's not in the XOs' mfg data)
#    then you need to pass --fullkey 
#  - The expiry can be in 'days from now' or as an abs timestamp in the format
#    required by the signatures.

# Ensure we call the binaries that are in the same
# directory as this shell script
MYPATH=$(readlink -f $0)
LIBEXEC=$(dirname $MYPATH)

# Handle opts
fullkey=""
chainfile=""

while [ $# != 0 ] && [ ${1:0:1} == '-' ]; do
    case "$1" in
	--fullkey)
	    fullkey=" --fullkey ";
	    ;;
	--chain)
	    chainfile=$2
	    fullkey=" --fullkey "
	    shift;
	    ;;
	*)
	    echo "Unknown param $1" >> /dev/stderr
	    exit 1;
    esac
    shift
done

[ $# -lt 4 ] && echo Usage: $0 [--fullkey] [--chain sigfile] serial-number [days|expire] signingkey targetkey [outfile] && exit 1

sn=$1
expire=$2
mkey=$3
tkey=$4

if [ $# -ge 5 ]; then
  outfile=$5
else
  outfile=/dev/stdout
fi

mkeyhex=`$LIBEXEC/key01 $mkey.public`
tkeyhex=`$LIBEXEC/key01 $tkey.public`


if [[ ${#expire} != 16 || "${expire:8:1}" != "T" || "${expire:15:1}" != "Z" ]]; then
    expire=`$LIBEXEC/futureday.py $expire`
    if [ $? != 0 ]; then
	echo "unrecognised date format" >> /dev/stderr
	exit 1
    fi
fi

if [ "$chainfile" == "" ]; then
    # "key01" has a trailing newline
    # - our backticks earlier ate it...
    echo $sn:$expire:$tkeyhex | $LIBEXEC/sig01 $fullkey --v2 $expire sha256 $mkey >$outfile
else
    # - strip the trailing newline from the sigfile we chain on
    # - strip the leading 'sig02: ' from the addition
    ( head -c -1 "$chainfile" ; (echo $sn:$expire:$tkeyhex | $LIBEXEC/sig01 $fullkey --v2 $expire sha256 $mkey | tail -c +7 ) ) >$outfile
fi
