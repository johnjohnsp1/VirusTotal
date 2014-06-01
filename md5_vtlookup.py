'''
The MIT License (MIT)

Copyright (c) 2013 Patrick Olsen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Author: Patrick Olsen
Email: patrickolsen@sysforensics.org
Twitter: @patrickrolsen
'''

import sys, os
import argparse
import requests

parser = argparse.ArgumentParser(description='Look up hashes against a white list then look at VT.')
parser.add_argument('-wl', '--whitelist', help='Path to your whitelist.')
parser.add_argument('-bl', '--blacklist', help='Path to the dumped hashes.')

args = parser.parse_args()

if args.whitelist:
    wl = open(args.whitelist, 'r').readlines()
else:
    print "You need to specify the whitelist."
if args.blacklist:
    bl = open(args.blacklist, 'r').readlines()
else:
    print "You need to specify the hashes from your dump."

white_list = []
black_list = []

for wl_hashes in wl:
    white_list.append(wl_hashes.strip())

for bl_hashes in bl:
    black_list.append(bl_hashes.strip())

for bl_file in black_list:
    blfile = bl_file.split("  ")[0]
    blpath = bl_file.split("  ")[1]
    if blfile in white_list:
        pass
    else:
        ###################################
        # You need to insert your API Key #
        ###################################
        params = {'apikey': '<API_KEY>', 'resource': blfile}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
        json_response = response.json()
        #print json_response['verbose_msg']

        if json_response['response_code'] == 0:
            print blfile, blpath + " has not been scanned before."
        else:
            if json_response['positives'] >= 1:
                print blfile, blpath, json_response['positives'],"/",json_response['total'], \
                        "McAfee: ", json_response['scans']['McAfee']['result'], \
                        json_response['permalink']
            else:
                print blfile, blpath, json_response['positives'],"/",json_response['total']