#!/bin/sh

# Create a tree with the files server.pub & server.pri in a directory for server
# Usage: cp-server-dirs  directory_with_server_keys destination_directory
# Example:
# 
# Notes:
#

# Ensure we call the binaries that are in the same
# directory as this shell script
MYPATH=$(command -v $0 | xargs readlink -f )
LIBEXEC=$(dirname $MYPATH)

# Handle opts
server_keys_dir=$1
xs_activation_dir=$2

[ $# -lt 2 ] \
    && echo "Usage: $0 directory_with_server_keys destination_directory" \
    && exit 1

echo server_key_dir
echo $server_key_dir

echo xs_activation_dir
echo $xs_activation_dir
sufix=".private"

for FILE in $(/bin/ls ${server_key_dir}/*${sufix}) 
do
	SCHOOL_NAME=`basename ${FILE}`
	#SCHOOL_NAME=${FILE##*/}
	SCHOOL_NAME=${SCHOOL_NAME%%.*}
	echo $SCHOOL_NAME
	mkdir ${xs_activation_dir}/${SCHOOL_NAME}
	# copy private key
	cp ${FILE} ${xs_activation_dir}/${SCHOOL_NAME}/server.pri
	PUB_FILE=`dirname ${FILE}`/${SCHOOL_NAME}.public
	cp ${PUB_FILE} ${xs_activation_dir}/${SCHOOL_NAME}/server.pub
	pushd ${xs_activation_dir}/${SCHOOL_NAME}
        sha1sum *.pub *.pri > manifest.sha1
	popd
done
