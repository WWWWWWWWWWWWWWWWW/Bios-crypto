#!/usr/bin/python 
""" Write delegations (usually for delegated leases) for a single group of
    laptops (e.g. a school), using a specific master key and server key.

    Input file: CSV, one laptop per line, format:
        SN,UUID
    
    Output: delegations on standard output

    Authors: Martin Langhoff <martin@laptop.org> and Daniel Drake
    Copyright: One Laptop per Child
    License: GPLv2
"""

from subprocess import call, check_call
import os.path, sys, os, re, tempfile, shutil, stat, csv, datetime
from subprocess import Popen, PIPE
from optparse import OptionParser

def main():
    basedir = os.path.dirname(os.path.realpath(sys.argv[0]))
    usagestr = '%prog [--options] <inputfile> <expiry> <masterkey> <serverkey>'
    parser = OptionParser(usage=usagestr)
    (opts, args) = parser.parse_args()

    if len(args) != 4:
        parser.print_help()
        exit(1)

    inputfile = args[0]
    if not os.path.isfile(inputfile):
        print >>sys.stderr, "Input file %s does not exist" % inputfile
        exit(1)

    expiry = args[1]
    if re.match('\d+$', expiry):
        expiry = int(expiry)
        expiry = (datetime.datetime.utcnow() \
            + datetime.timedelta(days=expiry)).strftime("%Y%m%dT%H%M%SZ")
    elif not re.match('\d{8}T\d{6}Z$', expiry):
        sys.stderr.write("Expiry %s is not understood\n" % key)
        exit(1)

    masterkey = args[2]
    masterkeypath = masterkey + '.private'
    if not os.path.isfile(masterkeypath):
        print >>sys.stderr, "Key %s does not exist" % masterkeypath
        exit(1)

    serverkey = args[3]
    serverkeypath = serverkey + '.public'
    if not os.path.isfile(serverkeypath):
        print >>sys.stderr, "Key %s does not exist" % serverkeypath
        exit(1)

    # init a reader
    r = csv.reader(open(inputfile,'r'))
    for row in r:
        sn      = row[0]
        uuid    = row[1]
        
        p = Popen([basedir+'/make-delegation.sh', sn, expiry, masterkey, serverkey], stdout=PIPE)
        buf = p.communicate()[0]
        if p.returncode != 0:
            sys.stderr.write("Error calling make-delegation\n")
            exit(1)

        # write a del01 preamble that shows sn/uuid
        print "del01:", sn, uuid,

        # and then the delecation itself:
        print buf,
    
    exit(0)

if __name__ == '__main__': main ()
