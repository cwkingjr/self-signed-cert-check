#!/usr/bin/env python

# Author: Chuck King
# Date: 2013-09-30
# Reason: Take a list of domains and exclusions and actively poll the
# domains (not the exclusions) to harvest their certificate, then use
# OpenSSL to compare the Issuer Organization Name to the Subject
# Organization Name, declaring matches as (non-deterministice) 
# self-signed certs. Cache results to speed up the process on 
# subsequent runs.  This script is only a proof of concept and hasn't
# been completed.  It still needs things like:
# - convert to use the python OpenSSL module
# - add default list, exclusion, cache files from home dir if not 
#   provided on command line
# - expire cache entries after some optional time period

### License ###
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
### License ###

import datetime
import optparse
import os
from os.path import expanduser
import re
import ssl
import subprocess
import sys
import tempfile

global exclusions
exclusions = {}

global cache
cache = {}


class Exclusion(object):

    """Simple container for exlusion entry"""

    def __init__(self, domain, port=443, comment=None):
        self.domain = domain
        self.port = port
        self.comment = comment

    def __str__(self):
        if self.comment:
            return "%s|%d#%s" % (self.domain, self.port, self.comment)
        else:
            return "%s|%d" % (self.domain, self.port)


class Cache(object):

    """Simple container for cache entry"""

    def __init__(self, domain, port, poll_date, results_text):
        self.domain = domain
        self.port = port
        self.poll_date = poll_date
        self.results_text = results_text
        
    def __str__(self):
        return "%s|%d|%s|%s" % (self.domain, self.port, self.poll_date, self.results_text)


def get_server_cert(addr_tuple):

    """Example addr_tuple = ('facebook.com', 443) """

    try:
        return ssl.get_server_certificate(addr_tuple, ssl_version=ssl.PROTOCOL_SSLv23, ca_certs=None) 
    except Exception as e:
        print "[+]: Could not connect to [%s] using SSL v2 or V3" % addr_tuple[0]
        print e
        return None

def process_cert(pemcert, addr):
    
    """ Decode with OpenSSL, then check for matching Issuer/Subject O values"""

    global cache

    msg = ''

    f = tempfile.NamedTemporaryFile(delete=False) 
    cert_file_name = f.name
    f.write(pemcert)
    f.close()

    try:
        cert_text = subprocess.check_output(["openssl", "x509", "-text", "-noout", 
                                        "-in", cert_file_name])
    except Exception as e:
        print "[+]: Problem calling openssl for [%s] certificate" % addr_tuple[0]
        print e
        return 
    finally:
        os.unlink(cert_file_name)
        
    issuer = re.search(r'Issuer:.*(O=[^,]*)', cert_text)
    subject = re.search(r'Subject:.*(O=[^,]*)', cert_text)

    if not issuer or not subject:
        msg = "[SSC]: Domain [%s] presumed self-signed - lack of Issuer/Subject O's" % addr[0]

    if issuer and subject:

        if issuer.group(1) != subject.group(1):
            msg = "[-]: Domain [%s], Issuer: %s, Subject: %s" % (addr[0], issuer.group(1), subject.group(1))

        if issuer.group(1) == subject.group(1):
            msg = "[SSC]: Domain [%s] matching Issuer & Subject 'O' of %s" % (addr[0], issuer.group(1))

    if msg == '':
        print "[+]: Problem processing [%s] certificate" % addr_tuple[0]
    else:
        print msg

        # add this record to the cache
        mykey = "%s|%d" % (addr[0], addr[1])
        mydate = datetime.date.today().isoformat() 
        cache[mykey] = Cache(domain=addr[0], port=addr[1], poll_date=mydate, results_text=msg)


def processOptions():
    """ process commandline options """
    usage = """usage: ./%prog [options]
use -h for help / option descriptions
"""

    parser = optparse.OptionParser(usage)

    parser.add_option("-i", "--in-file", dest="infile", help="""Path to domains-to-process file. Format is domain-name.tld|server-port, one entry per line.  Example: yahoo.com|443""")
    parser.add_option("-c", "--cache-file", dest="cachefile", help="""Path to processed domains cache file. Format is domain-name|server-port|date-polled|results text.  File can be empty to start.""")
    parser.add_option("-e", "--exclude-file", dest="excludefile", help="""Path to domain exclusion file. This file includes names that will not be checked and is manually maintained to exclude certain domains.  Format is domain-name.tld|port#user comment.  Example: google.com|port # google signs their own certs.""")

    (options, args) = parser.parse_args()

    if not options.infile:
        print "[+] -i | --in-file required. Ex: --in-file=domains-to-check.txt"
        sys.exit(1)
    else:
        # make sure the file exists
        if not os.path.isfile(options.infile):
            print "[+] --in-file is not a file: %s" % (options.infile)
            sys.exit(1)

    if not options.cachefile:
        print "[+] -c | --cache-file required. Ex: --cache-file=self-signed-cert-check.cache"
        sys.exit(1)
    else:
        # make sure the file exists
        if not os.path.isfile(options.cachefile):
            print "[+] --cache-file is not a file: %s" % (options.cachefile)
            sys.exit(1)

    if options.excludefile:
        # make sure the file exists
        if not os.path.isfile(options.excludefile):
            print "[+] --exclude-file is not a file: %s" % (options.excludefile)
            sys.exit(1)

    return (options, args)

def load_exclusions():

    # Exclusion format: domain-name.tld|optional port # optional user comment

    global exclusions
    global options

    with open(options.excludefile, 'r') as f:

        for line in f:

            # track for error reporting
            original_line = line

            # skip comments and blank lines
            if line.startswith('#') or line.strip() == '':
                continue

            comment = ''

            # extract any embedded comments and reset line value
            if '#' in line:
                line, comment = [x.strip() for x in line.split('#')]

            # if there's a port listed 
            if '|' in line:
                domain, port = [x.strip() for x in line.split('|')]
                
                if port == '':
                    port = 443 
                else:
                    port = int(port)
            else:
                domain = line.strip()
                port = 443

            if domain == '' or not -1 < port < 65536:
                print "[+] can't process exclusion line: %s" % original_line
                continue
                
            myexclusion = Exclusion(domain=domain, port=port, comment=comment)                

            exclusions[domain + '|' + str(port)] = myexclusion


def load_cache():

    # Cache format: domain-name.tld|port|poll_date|results_text

    global cache
    global options

    with open(options.cachefile, 'r') as f:

        for line in f:
 
            # skip comments and blank lines
            if line.startswith('#') or line.strip() == '':
                continue

            # skip malformed lines
            if not '|' in line or len(line.split('|')) < 4:
                continue

            # extract the fields with strip cleanup
            domain, port, poll_date, results_text = [x.strip() for x in line.split('|')]

            if domain == '' or port == '' or poll_date == '' or results_text == '':
                continue

            port = int(port)

            # port should be between 0-65535 inclusive
            if not -1 < port < 65536:
                continue
                
            mycache = Cache(domain=domain, port=port, poll_date=poll_date, results_text=results_text) 

            cache[domain + '|' + str(port)] = mycache


def dump_cache():

    global cache
    global options

    print "[-] Writing updated cache file"

    with open(options.cachefile, 'w') as f:
        for mykey in sorted(cache.keys()):
            f.write(str(cache[mykey]) + "\n")


def main():

    global options, args
    global exclusions, cache

    print "[-] = INFO, [+] = ERROR, [SSC] = Self Signed Certificate"

    (options, args) = processOptions()

    load_exclusions()
    print "[-] Loaded %d exclusion entries" % len(exclusions)

    load_cache()
    print "[-] Loaded %d cache entries" % len(cache)

    # read in file
    with open(options.infile, 'r') as f:

        for line in f:

            # skip comments and blank lines
            if line.startswith('#') or line.strip() == '':
                continue

            # if there's a port listed 
            if '|' in line:

                # we should only have two elements surrounding one pipe
                if len(line.split('|')) != 2:
                    print "[+] skipping infile line: %s" % line
                    continue

                domain, port = [x.strip() for x in line.split('|')]
                
                if port == '':
                    port = 443 
                else:
                    port = int(port)
            else:
                domain = line.strip()
                port = 443

            if domain == '' or port == '':
                print "[+] skipping infile line: %s" % line
                continue

            port = int(port)

            mykey = "%s|%d" % (domain, port)

            if mykey in exclusions:
                continue

            if mykey in cache:
                print "%s [cached %s]" % (cache[mykey].results_text, cache[mykey].poll_date)
            else:
                addr = (domain, port)
                mycert = get_server_cert(addr)

                if mycert:
                    process_cert(mycert, addr)

    # write a new cache file
    dump_cache()



if __name__ == "__main__":
    main()
