#!/bin/sh

# Make a lease file
# Usage: make-lease.sh [--v2] [--chain delegfile] [--signingkey keyname] serial-number nonce [outfile]
# Example:
# make-lease.sh SHF706002A7 8BF9AC40-26F8-4BCC-A699-BE51FD366419 1 [outfile]

# Ensure we call the binaries that are in the same
# directory as this shell script
MYPATH=$(readlink -f $0)
LIBEXEC=$(dirname $MYPATH)

# Handle opts
fullkey=""
chainfile=""
signingkey="lease"
v2=""

while [ $# != 0 ] && [ ${1:0:1} == '-' ]; do
    case "$1" in
	--v2)
	    v2=" --v2 "
	    ;;
	--fullkey)
	    fullkey=" --fullkey ";
	    ;;
	--chain)
	    chainfile=$2
	    fullkey=" --fullkey "
	    v2=" --v2 "
	    shift;
	    ;;
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
    && echo "Usage: $0 [--chain delegfile] [--signingkey keyname] serial-number nonce [outfile]" >> /dev/stderr \
    && exit 1

sn=$1
nonce=$2

if [ $# -ge 3 ]; then
  outfile=$3
else
  outfile=/dev/stdout
fi

expire=`$LIBEXEC/futureday.py`
tstamp=`date -u '+%Y%m%dT%H%M%SZ'`

header="time01: $sn $tstamp "
payload="$sn:$nonce:$tstamp"
if [ "$chainfile" == "" ]; then
    # non-chained v2
    ( echo -n "$header"; 
	echo -n "$payload" \
	    | $LIBEXEC/sig01 --v2 $expire $fullkey sha256 $signingkey ) >$outfile
    
else
    # v2, chained
    ( echo -n "$header";
	head -c -1 "$chainfile" ;
	echo -n "$payload" \
	    | $LIBEXEC/sig01 --v2 $expire $fullkey sha256 $signingkey \
	    | tail -c +7 ) >$outfile
fi

