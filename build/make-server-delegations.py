#!/usr/bin/python 
""" Write delegations (usually for delegated leases)
    for each server, based on XS SNs from a CSV file
    and the server's public keys.

    Author: Martin Langhoff <martin@laptop.org>
    Copyright: One Laptop per Child
    License: GPLv2
"""

from subprocess import call, check_call
import os.path, sys, os, re, tempfile, shutil, stat, csv, datetime
from subprocess import Popen, PIPE
from optparse import OptionParser

def main():
    usagestr = '%prog [--csv /path/to/file.csv] [--outdir /tmp] [--serverkeys=/path/to/serverkeys/] [--cvsdialect=excel|excel-tab] <expiry> <signingkey>'
    parser = OptionParser(usage=usagestr)
    parser.add_option('--csv',
                      dest='csv',
                      default='/var/lib/olpc-bios-crypto/servers-xos.csv')
    parser.add_option('--outdir',
                      dest='outdir',
                      default='/var/lib/olpc-bios-crypto/server-leases')
    parser.add_option('--serverkeys',
                      dest='serverkeys',
                      default='/var/lib/olpc-bios-crypto/server-keys')
    parser.add_option('--csvdialect',
                      dest='csvdialect',
                      default='excel')
    (opts, args) = parser.parse_args()

    if len(args) != 2:
        sys.stderr.write('Usage: '+usagestr+"\n")
        exit(1)
        
    expiry = args[0]
    if re.match('\d+$', expiry):
        expiry = int(expiry)
        expiry = (datetime.datetime.utcnow() \
            + datetime.timedelta(days=expiry)).strftime("%Y%m%dT%H%M%SZ")
    elif not re.match('\d{8}T\d{6}Z$', expiry):
        sys.stderr.write("Expiry %s is not understood\n" % key)
        exit(1)

    key = args[1]
    keypath = key + '.private'
    if not os.path.exists(keypath):
        sys.stderr.write("Key %s does not exist\n"
                         % keypath)
        exit(1)
    
    if not os.path.exists(opts.csv):
        sys.stderr.write("Input file %s does not exist\n"
                         % opts.csv)
        exit(1)

    basedir = os.path.dirname(sys.argv[0])

    tmpfiles = {}

    # init a reader
    r = csv.reader(open(opts.csv))
    for row in r:
        svrname = row[0]
        sn      = row[1]
        uuid    = row[2]
        
        if not os.path.exists(os.path.join(opts.serverkeys, svrname+'.public')):
            sys.stderr.write("Server key file %s does not exist\n"
                         % opts.csv)
            exit(1)

        if not os.path.exists(opts.outdir):
            sys.stderr.write("Outdir %s does not exist\n"
                         % opts.outdir)
            exit(1)

        fname = os.path.join(opts.outdir, svrname+'.sig')


        if not fname in tmpfiles:
            tmpfiles[fname] = tempfile.mkstemp()
        tmpfh = tmpfiles[fname][0]

        print "Creating /keykey %s " % (fname)
        p = Popen([basedir+'/make-delegation.sh', sn, expiry, key, os.path.join(opts.serverkeys,svrname) ], stdout=PIPE)
        buf = ''
        while p.returncode == None:
            buf += p.communicate()[0]
        if p.returncode != 0:
            sys.stderr.write("Error calling make-delegation\n")
            exit(1)

        # write a preamble that shows what sn/uuid
        # we're delegating
        os.write(tmpfiles[fname][0],
                 "del01: %s %s " % (sn, uuid))

        # and then the delecation itself:
        os.write(tmpfh, buf)


    for dname, tmp in tmpfiles.iteritems():
        # tmp=[fh, tmpname]
        os.close(tmp[0])
        os.rename(tmp[1],dname)
        

if __name__ == '__main__': main ()
