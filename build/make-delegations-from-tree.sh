#!/bin/bash
#
# Write delegations for a group of schools, with a specific master key.
#
# -o DAYS enables optimize mode: Automatically generate and use a  .lastrun
# output file too, which allows us to not generate delegations if:
#  1. the output file exists, and
#  2. the .lastrun file indicates that the xo.csv input list has not changed
#     since last run, and
#  3. the .lastrun file indicates that delegations were last generated less than
#     DAYS days ago.
#
# Authors: Gonzalo Odiard and Daniel Drake
# License: GPLv2
#
set -e

OPTIMIZE=""
while getopts "o:" OPTION
do
 case $OPTION in
 o)
 OPTIMIZE=$OPTARG;;

 esac
done
shift $(($OPTIND - 1))

if [ $# -lt 5 ];
then 
	echo "Usage make-delegations-by-tree [-o DAYS] delegs_dir expiration masterkey server_keys_dir output_file_name"
	exit 1
fi

MYPATH=$(command -v $0 | xargs readlink -f )
LIBEXEC=$(dirname $MYPATH)

DELEG_DIR=$1
EXPIRATION=$2
MASTERKEY=$3
SERVERKEYS_DIR=$4
OUT_FILE_NAME=$5

regenerate_needed() {
	local infile=$1
	local outfile=$2
	local lastrun=$outfile.lastrun

	# if not in optimize mode, we need to generate
	[ -n "$OPTIMIZE" ] || return 0

	# if we don't have lastrun or outfile, we need to generate
	[ -f "$outfile" -a -f "$lastrun" ] || return 0

	# if md5sum doesn't match, we need to generate
	md5sum --status -c $lastrun || return 0

	# get time of last run
	lastrun_time=$(stat -c '%Y' $lastrun)

	# calculate when we'd need to generate again
	nextrun_time=$((lastrun_time + (60 * 60 * 24 * $OPTIMIZE)))

	# current time
	curtime=$(date +%s)

	# if we passed the specified number of days, we need generate
	[ $curtime -gt $nextrun_time ] && return 0

	return 1
}

for FILE in ${DELEG_DIR}/*/xo.csv
do
	SCHOOL_DIR=${FILE%/*}
	SCHOOL_NAME=${SCHOOL_DIR##*/}
	if ! [ -f ${SERVERKEYS_DIR}/${SCHOOL_NAME}.public ]; then
		echo "Not making delegations for ${SCHOOL_NAME}; no server key available"
		continue
	fi

	OUTFILE=${SCHOOL_DIR}/${OUT_FILE_NAME}
	if ! regenerate_needed "$FILE" "$OUTFILE"; then
		echo "Not making delegations for ${SCHOOL_NAME}; laptop list has not changed and delegations are fresh"
		continue
	fi

	echo "Making delegations for ${SCHOOL_NAME}"
	${LIBEXEC}/make-server-delegations.py ${FILE} ${EXPIRATION} ${MASTERKEY} ${SERVERKEYS_DIR}/${SCHOOL_NAME} > ${OUTFILE}
	if [ -n "$OPTIMIZE" ]; then
		md5sum $(readlink -f $FILE) > ${OUTFILE}.lastrun
	fi
done

