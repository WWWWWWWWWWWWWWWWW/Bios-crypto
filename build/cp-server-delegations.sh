#!/bin/sh

# Create a tree with the files server.pub & server.pri in a directory for server
# Usage: cp-server-dirs src dest
# Example:
# 
# Notes:
#

set -e

# Ensure we call the binaries that are in the same
# directory as this shell script
MYPATH=$(command -v $0 | xargs readlink -f )
LIBEXEC=$(dirname $MYPATH)

# Handle opts
src=$1
dest=$2


[ $# -lt 2 ] \
    && echo "Usage: $0 source dest " \
    && exit 1

for TYPE in d-lease d-oats; do
	for FILE in $(/bin/ls ${src}/${TYPE}/*.sig) 
	do
		SCHOOL_NAME=`basename ${FILE}`
		#SCHOOL_NAME=${FILE##*/}
		SCHOOL_NAME=${SCHOOL_NAME%%.*}
		#echo $SCHOOL_NAME
		mkdir -p ${dest}/${SCHOOL_NAME}
		# copy delegation
		cp ${FILE} ${dest}/${SCHOOL_NAME}/${TYPE}.sig
		# this will happen twice -- but we won't
		# stress about that
		pushd ${dest}/${SCHOOL_NAME}
		sha1sum *.sig > manifest.sha1
		popd
	done
done

