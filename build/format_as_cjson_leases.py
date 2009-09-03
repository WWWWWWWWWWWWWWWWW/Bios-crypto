#!/usr/bin/python

import sys
import bitfrost.util.json as cjson
import fileinput
import re

leases = {}
for line in fileinput.input():
    if line:
        m = re.match('act\d\d: (.+?) ', line)
        if m:
            sn = m.group(1)
            if sn in leases:
                leases[sn] = leases[sn] + line
            else:
                leases[sn] = line

sys.stdout.write(cjson.write([1, leases]))
