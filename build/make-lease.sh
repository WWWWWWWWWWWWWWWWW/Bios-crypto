#!/bin/sh

# Make a lease file
# Usage: make-lease.sh [--v2] [--chain delegfile] [--signingkey keyname] serial-number uuid [days|expire] [outfile]
# Example:
# make-lease.sh SHF706002A7 8BF9AC40-26F8-4BCC-A699-BE51FD366419 1 [outfile]

[ $# -lt 3 ] && echo Usage: $0 [--v2] [--chain delegfile] [--signingkey keyname] serial-number uuid [days|expire] [outfile] && exit 1

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

if [ "$chainfile" == "" ]; then
    if [ "$v2" == "" ]; then
	( echo -n "act01: $sn K $expire "; 
	    echo -n $sn:$uu:K:$expire | ./sig01 $fullkey sha256 $signingkey ) >$outfile
    else 
	# non-chained v2
	( echo -n "act01: $sn K $expire "; 
	    echo -n $sn:$uu:K:$expire | ./sig01 --v2 $expire $fullkey sha256 $signingkey ) >$outfile
    fi
else
    # v2, chained
    ( echo -n "act01: $sn K $expire ";
	head -c -1 "$chainfile" ;
	echo -n $sn:$uu:K:$expire | ./sig01 --v2 $expire $fullkey sha256 $signingkey | tail -c +7 ) >$outfile
fi