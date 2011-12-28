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

[ $# != 6 ] \
    && echo "Usage: $0 serial uuid currentrtc nonce newrtc leasekey" >> /dev/stderr \
    && exit 1

SN="$1"
UUID="$2"
CURRENTRTC="$3"
NONCE="$4"
NEWRTC="$5"
SIGNINGKEY="$6"

# Ensure nonce is zero-padded with length 10
NONCE="0000000000$NONCE"
NONCE="${NONCE: -10}"

echo -n ${SN}:${UUID}:${CURRENTRTC}:${NONCE}:${NEWRTC} >signed-data

$LIBEXEC/sig01 sha256 ${SIGNINGKEY} signed-data >this-signature
echo -n rtc01: ${SN} ${CURRENTRTC} ${NONCE} ${NEWRTC} "" | cat - this-signature
# rm -f signed-data this-signature

