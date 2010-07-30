#!/bin/sh

# Make a lease file from CSV
# Usage: make-lease.sh [--v2] [--chain delegfile] [--signingkey keyname] laptops.csv [days|expire]
# Example:
# make-lease.sh laptops.csv 1

# Ensure we call the binaries that are in the same
# directory as this shell script
MYPATH=$(command -v $0 | xargs readlink -f )
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

[ $# -lt 1 ] \
    && echo "Usage: $0 [--v2] [--chain delegfile] [--signingkey keyname] laptops.csv [days|expire]" >> /dev/stderr \
    && exit 1

FILE=$1
expire=$2

if [[ ${#expire} != 16 || "${expire:8:1}" != "T" || "${expire:15:1}" != "Z" ]]; then
    expire=`$LIBEXEC/futureday.py $expire`
    if [ $? != 0 ]; then
	echo "unrecognised date format" >> /dev/stderr
	exit 1
    fi
fi

for LINE in `cat "$FILE"`; do
    sn=`echo -n "$LINE"| sed 's/\r//; s/ //g' | cut -d, -f1`
    uu=`echo -n "$LINE"| sed 's/\r//; s/ //g' | cut -d, -f2`

    if [ "$v2" == "" ]; then
	( echo -n "act01: $sn K $expire "; 
	    echo -n $sn:$uu:K:$expire | $LIBEXEC/sig01 $fullkey sha256 $signingkey )
    else
	payload="$sn:$expire:$sn:$uu:K:$expire"
	if [ "$chainfile" == "" ]; then
	    # non-chained v2
	    ( echo -n "act01: $sn K $expire "; 
		echo -n $payload \
		    | $LIBEXEC/sig01 --v2 $expire $fullkey sha256 $signingkey )
	else
            # v2, chained
	    ( echo -n "act01: $sn K $expire ";
		head -c -1 "$chainfile" ;
		echo -n $payload \
		    | $LIBEXEC/sig01 --v2 $expire $fullkey sha256 $signingkey \
		    | tail -c +7 )
	fi
    fi
done
