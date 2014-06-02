Virus Total Lookup Scripts
===========================

This is just a small collection of VirusTotal lookup scripts i've written to help automate a few things.


Autoruns Virus Total Lookup
============================
This will take a text output from Microsoft's Autoruns tool, "parse it", then look up the hashes on VT.

autorunsc.exe -f /accepteula * >> Autostart_All.txt

autohash.py -h
		usage: autohash.py [-h] [-f INFILE]

		Take autoruns txt output and look the hashes up on VirusTotal.

		optional arguments:
		  -h, --help            show this help message and exit
		  -f INFILE, --infile INFILE
		                        Path to autoruns text file.

autoruns_vtlookup.py -f Autostart_All.txt

		c:\program files (x86)\dell\upsmanagementsoftware\upsms.exe 
		0a15e929756ab59eee6115996bf09313 1 / 53 McAfee:  None https://www.virustotal.com/file/9214919c458dd9472276330f1669249ec53c594c3af735dbfd297c062ff6d85e/analysis/1401228199/ 
		
		c:\program files (x86)\kaspersky lab\kaspersky small office security 3\avp.exe 
		cf75b4d3cdfb3f14b272ea6799a9f03b 0 / 52 
		
		c:\windows\system32\unregmp2.exe 
		51df02e674a47191aa58111cb157174d 0 / 52 

If the positives are >= 1 it will print the McAfee malware label and also print a link to the suspect file.

MD5deep Virus Total Lookup
=============================
This "parses" the output from md5deep, bounces up the hashes against a whitelist, then the remaining files that are not in the whitelist it will query virus total.

md5deep.exe -r -l -s "<path>" >> Hashes.txt

md5_vtlookup -h
		
		usage: vt.py [-h] [-wl WHITELIST] [-bl BLACKLIST]

		Look up hashes against a white list then look at VT.

		optional arguments:
		  -h, --help            show this help message and exit
		  -wl WHITELIST, --whitelist WHITELIST
		                        Path to your whitelist.
		  -bl BLACKLIST, --blacklist BLACKLIST
		                        Path to the dumped hashes.


md5_vtlookup.py -wl whitelist.txt -bl Hashes.txt

		2e83ec18c281102c5dbb423f6df57cf3 C:\Windows\bootstat.dat has not been scanned before.
		b30afc59f449c93d7030cd85d28a8c45 C:\Windows\certenroll.log has not been scanned before.
		bd3d4eabd379a59f336b099a48d382f0 C:\Windows\CertReq.log has not been scanned before.
		1ccc16aa7c32c1395fa95311229fbd83 C:\Windows\certutil.log has not been scanned before.
		313a22f8f16b6bc1cfe857737dfc2935 C:\Windows\aksdrvsetup.log has not been scanned before.
		963f5385ff22824af6a9b1429555d4a2 C:\Windows\certocm.log has not been scanned before.
		fbcbc70c8f2d4ce235f32151860ee79d C:\Windows\dchcfg32.exe 0 / 47
		9966b5dfeb602224d1854da81e603cf7 C:\Windows\dcmdev64.exe 0 / 48
		16c4d2e3935f1a0934d115959426268c C:\Windows\DELL_VERSION has not been scanned before.
		682ae0ffa6a865a8d137c43139bb4bcd C:\Windows\diagerr.xml 0 / 47
		49d9fb48f4c2078fa8e663d7c5758259 C:\Windows\DirectX.log has not been scanned before.
		5bf963f4626737e5c342fb58827a6718 C:\Windows\DtcInstall.log has not been scanned before.
		c696428435782e9c7646f590a360b85d C:\Windows\fmprog.ini has not been scanned before.
		37261c0b333a74748022e98f42d57740 C:\Windows\malware_example.exe 30 / 52 McAfee:  Artemis!37261C0B333A https://www.virustotal.com/file/0b2c2b1e0b4969f1b3129627ca1c3cb5d1ac8509eda7fccd39995dfa11a3f30f/analysis/1401458794/
