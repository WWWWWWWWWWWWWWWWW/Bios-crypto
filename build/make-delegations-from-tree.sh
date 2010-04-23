#/bin/bash
# Write delegations for a group of schools, with a specific master key.
# Authors: Gonzalo Odiard and Daniel Drake
# License: GPLv2
#
set -e
if [ $# -lt 5 ];
then 
	echo "Usage make-delegations-by-tree [-a] delegs_dir expiration masterkey server_keys_dir output_file_name"
	exit 1
fi

MYPATH=$(readlink -f $0)
LIBEXEC=$(dirname $MYPATH)

ACTIVATION=""
while getopts a OPTION
do
	case $OPTION in
		a)
		ACTIVATION="--activation";;
		
	esac
done
shift $(($OPTIND - 1))
DELEG_DIR=$1
EXPIRATION=$2
MASTERKEY=$3
SERVERKEYS_DIR=$4
OUT_FILE_NAME=$5

for FILE in ${DELEG_DIR}/*/xo.csv
do
	SCHOOL_DIR=${FILE%/*}
	SCHOOL_NAME=${SCHOOL_DIR##*/}
	if [ -f ${SERVERKEYS_DIR}/${SCHOOL_NAME}.public ];
	then
		echo "Making delegations for ${SCHOOL_NAME}"
		${LIBEXEC}/make-server-delegations.py ${ACTIVATION} ${FILE} ${EXPIRATION} ${MASTERKEY} ${SERVERKEYS_DIR}/${SCHOOL_NAME} > ${SCHOOL_DIR}/${OUT_FILE_NAME}
	else
		echo "Not making delegations for ${SCHOOL_NAME}; no server key available"
	fi
done 
