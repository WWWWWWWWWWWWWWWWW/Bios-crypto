#!/usr/bin/python
# Usage: ./futureday.py [days]     - Default is 1 day

import datetime
import sys

if len(sys.argv) >= 2:
  ndays=int(sys.argv[1])
else:
  ndays=1

print (datetime.datetime.utcnow() + datetime.timedelta(days=ndays)).strftime("%Y%m%dT%H%M%SZ")
