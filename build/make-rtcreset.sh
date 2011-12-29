#!/bin/bash

# Make a rtcreset.sig file
# Usage: make-rtcreset serial uuid currentrtc nonce newrtc leasekey
# Example:
# make-rtcreset SHC005007B7 1273E0EC-AEF1-9FF6-45B2-FB706DC24B8D 20110512T003512Z 0000000135 20110412T003512Z testkeys/lease
# The output file is rtcreset.sig

# Ensure we call the binaries that are in the same
# directory as this shell script
MYPATH=$(readlink -f $0)
LIBEXEC=$(dirname $MYPATH)

# Handle opts
CHAINFILE=""
SIGNINGKEY="lease"
V2=""

while [ $# != 0 ] && [ ${1:0:1} == '-' ]; do
    case "$1" in
	--v2)
	    V2=" --v2 "
	    ;;
	--chain)
	    CHAINFILE=$2
	    V2=" --v2 "
	    shift;
	    ;;
	--signingkey)
	    SIGNINGKEY=$2
	    shift;
	    ;;
	*)
	    echo "Unknown param $1" >> /dev/stderr
	    exit 1;
    esac
    shift
done

[ $# != 5 ] \
    && echo "Usage: $0 [--chain delegfile] [--signingkey keyname] serial uuid currentrtc nonce newrtc" >> /dev/stderr \
    && exit 1

SN="$1"
UUID="$2"
CURRENTRTC="$3"
NONCE="$4"
NEWRTC="$5"

# Ensure nonce is zero-padded with length 10
NONCE="0000000000$NONCE"
NONCE="${NONCE: -10}"

payload=${SN}:${UUID}:${CURRENTRTC}:${NONCE}:${NEWRTC}
echo -n rtc01: ${SN} ${CURRENTRTC} ${NONCE} ${NEWRTC} ""
if [ "$V2" == "" ]; then
	echo -n $payload | $LIBEXEC/sig01 sha256 ${SIGNINGKEY}
else
	payload="${SN}:00000000T000000Z:${payload}"
    if [ "$CHAINFILE" == "" ]; then
		# non-chained v2
		echo -n $payload | \
			$LIBEXEC/sig01 --v2 00000000T000000Z sha256 $SIGNINGKEY
	else
		# chained v2
		head -c -1 "$CHAINFILE"
		echo -n $payload \
			| $LIBEXEC/sig01 --v2 00000000T000000Z --fullkey sha256 $SIGNINGKEY \
			| tail -c +7
	fi
fi

