#!/bin/sh

# Make a lease file
# Usage: make-lease.sh [--v2] [--chain delegfile] [--signingkey keyname] serial-number uuid [days|expire] [outfile]
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

[ $# -lt 3 ] \
    && echo "Usage: $0 [--v2] [--chain delegfile] [--signingkey keyname] serial-number uuid [days|expire] [outfile]" >> /dev/stderr \
    && exit 1

sn=$1
uu=$2
expire=$3

if [ $# -ge 4 ]; then
  outfile=$4
else
  outfile=/dev/stdout
fi

if [[ ${#expire} != 16 || "${expire:8:1}" != "T" || "${expire:15:1}" != "Z" ]]; then
    expire=`$LIBEXEC/futureday.py $expire`
    if [ $? != 0 ]; then
	echo "unrecognised date format" >> /dev/stderr
	exit 1
    fi
fi

if [ "$v2" == "" ]; then
    ( echo -n "act01: $sn K $expire "; 
	echo -n $sn:$uu:K:$expire | $LIBEXEC/sig01 $fullkey sha256 $signingkey ) >$outfile
else
    payload="$sn:$expire:$sn:$uu:K:$expire"
    if [ "$chainfile" == "" ]; then
	# non-chained v2
	( echo -n "act01: $sn K $expire "; 
	    echo -n $payload \
		| $LIBEXEC/sig01 --v2 $expire $fullkey sha256 $signingkey ) >$outfile
    
    else
        # v2, chained
	( echo -n "act01: $sn K $expire ";
	    head -c -1 "$chainfile" ;
	    echo -n $payload \
		| $LIBEXEC/sig01 --v2 $expire $fullkey sha256 $signingkey \
		| tail -c +7 ) >$outfile
    fi
fi
