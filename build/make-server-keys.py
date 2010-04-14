#!/usr/bin/python 
""" Write new keys for servers from a CSV file.

    Author: Martin Langhoff <martin@laptop.org>
    Copyright: One Laptop per Child
    License: GPLv2
"""

from subprocess import call, check_call
import os.path, sys, os, re, tempfile, shutil, stat, csv
from optparse import OptionParser

def main():
    parser = OptionParser(usage='%prog [--csv /path/to/file.csv] [--outdir /tmp] [--cvsdialect=excel|excel-tab]')
    parser.add_option('--csv',
                      dest='csv',
                      default='/var/lib/olpc-bios-crypto/servers.csv')
    parser.add_option('--outdir',
                      dest='outdir',
                      default='/var/lib/olpc-bios-crypto/server-keys')
    parser.add_option('--csvdialect',
                      dest='csvdialect',
                      default='excel')
    (opts, keynames) = parser.parse_args()

    basedir = os.path.dirname(os.path.realpath(sys.argv[0]))

    if not os.path.isdir(opts.outdir):
        sys.stderr.write("Outdir %s does not exist\n"
                         % opts.outdir)
        exit(1)
    

    # init a reader
    r = csv.reader(open(opts.csv))
    for row in r:
        svrname = row[0]
        keyfile = os.path.join(opts.outdir, svrname)
        print "Creating key %s{.private,.public} " % (keyfile)
        check_call([basedir+'/makekey', keyfile])


if __name__ == '__main__': main ()
