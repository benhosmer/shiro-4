#!/usr/bin/env python

# Reads stdin which is the result of a PUT to threadfix and examines
# the results for a set threshold of vulnerabilities.

# Usage Example:
# /bin/curl -H 'Accept: application/json' -X POST --form file=@dependency-check-report.xml 'https://threadfix.myservice.org | ./sspf.py

import sys
import os
import json

# The scan results we actually care about
criteria = ['highVulnCount', 'criticalVulnCount']

def sspf() :
    '''Parses the JSON response from threadfix and returns 1
    if there are more than 0 vulnerabilities found matching
    the levels set in criteria.
    '''
    if os.isatty(0):
        raise SystemExit(1, 'No input')
    else:
        try:
          response = json.load(sys.stdin)
        except ValueError:
          raise SystemExit(1, 'Not valid JSON')
    for index, value in enumerate(criteria):
        if response['object'].get(value) is None:
            raise SystemExit(1, 'Improper data reported')
        if response['object'].get(value):
            raise SystemExit(1, 'Vulnerabalities found')
        else:
            raise SystemExit(0)

if __name__ == '__main__':
    sspf()

