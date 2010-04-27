#!/usr/bin/python
# Take an input file, one laptop per line, of format:
# 	school,SN,UUID
#
# Create directories based on the school name, and place xo.csv output files
# there of format:
# 	SN,UUID
# The lines in the output files are sorted alphabetically
#
# Author: Daniel Drake
# License: GPLv2
#

import os
import os.path
import glob
import sys
import csv
import tempfile

def main():
    if len(sys.argv) != 3:
        print >>sys.stderr, "Usage: %s <csv_input> <output_tree>" % sys.argv[0]
        sys.exit(1)

    csv_input = sys.argv[1]
    output_tree = sys.argv[2]

    laptops = {}

    r = csv.reader(open(csv_input, "r"))
    for row in r:
        school = row[0]
        sn = row[1]
        uuid = row[2]

        if not school in laptops:
            laptops[school] = []

        laptops[school].append(sn + "," + uuid)

    for school, xolist in laptops.items():
        xolist.sort()
        outputdir = os.path.join(output_tree, school)
        outputfile = os.path.join(outputdir, "xo.csv")

        if not os.path.exists(outputdir):
            os.makedirs(outputdir)

        # do it atomically
        tempfd = tempfile.NamedTemporaryFile(delete=False)
        for laptop in xolist:
            print >>tempfd, laptop
        tempfd.close()
        os.rename(tempfd.name, outputfile)

if __name__ == "__main__":
    main()

