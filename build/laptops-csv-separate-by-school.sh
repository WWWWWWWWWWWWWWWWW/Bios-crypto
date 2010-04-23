#/bin/bash
# Take an input file, one laptop per line, of format:
# 	school,SN,UUID
#
# Create directories based on the school name, and place xo.csv output files
# there of format:
# 	SN,UUID
#
# Author: Gonzalo Odiard
# License: GPLv2
#
set -e
SERVERS_XO_FILE=$1
OUTPUT_TREE=$2

rm -f ${OUTPUT_TREE}/*/xo.csv || :

for LINE in $(<${SERVERS_XO_FILE})
do
	SCHOOL=${LINE%%,*}
	XO_DATA=${LINE:${#SCHOOL}+1}
	/bin/mkdir -p ${OUTPUT_TREE}/${SCHOOL}
	echo $XO_DATA >> ${OUTPUT_TREE}/${SCHOOL}/xo.csv
done

