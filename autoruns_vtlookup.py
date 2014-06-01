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

import argparse
import codecs
import re
import requests

parser = argparse.ArgumentParser(description='Take autoruns txt output and look the hashes up on VirusTotal.')
parser.add_argument('-f', '--infile', help='Path to autoruns text file.')

args = parser.parse_args()

if args.infile:
    input_file = args.infile
else:
    print "You need to specify your autoruns file."

def vtAutoScan(input_file):
	global hash_list
	hash_list = []
	file_line = []
	data = open(input_file, 'rb').readlines()
	for i in range(len(data)):
		#This section is pretty ghetto, but whatever works, works....
		if data[i].replace('\x00', '').strip().startswith("MD5"):
			filename = data[i-2].replace('\x00', '').strip()
			hashes = data[i].replace('\x00', '').strip()[10:]
			###################################
			# You need to insert your API Key #
			###################################
			params = {'apikey': '<API_KEY>', 'resource': hashes}
			response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
			json_response = response.json()

			if json_response['response_code'] == 0:
				print filename,"\n", hashes + " has not been scanned before.", "\n"
			else:
				if json_response['positives'] >= 1:
					print filename,"\n",hashes, json_response['positives'],"/",json_response['total'], \
                        					"McAfee: ", json_response['scans']['McAfee']['result'], \
                        					json_response['permalink'], "\n"
				else:
					print filename,"\n",hashes, json_response['positives'],"/",json_response['total'], "\n"
		else:
			pass


def main():
	vtAutoScan(input_file)
if __name__ == "__main__":
    main()