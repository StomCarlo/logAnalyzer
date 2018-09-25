#!/usr/bin/python
# RELEASED UNDER THE GNU GPLv3 LICENSE
# DNSBLS.py is tested and found compatible with Ubuntu 12.04 Server with Python 2.7.3
#
# INSTALL
# Simply download the script with you favorite tool (ex. wget) and run the script from where you placed it.
# 
# Use the software at your own risk!
# I can be contacted through the Ubuntu forums as the user MadsRC regarding the software.
############# CHANGELOG ################
# Changes since v. 1.1:
# * Removed the hardcoded list and made it as an imported list from the file "blacklists".
# * Added the option "--true" which nearly does the same as "-v". The difference is that "--true"
# returns whatever IP is registered in a given RBL list. "-v" only returns the value if it 
# starts with 127.
import socket, sys

# To add your own dns blacklists or remove some, just edit the below list.
	
def ip_reversed(ip, separator='.'):

    ipListe = ip.split(separator)
    ipListeReversed = []

    n = len(ipListe)
    while n != 0:
        ipListeReversed.append(ipListe[n-1])
        n -= 1
        continue

    return separator.join(ipListeReversed)
def check(ip):
	try:
		socket.inet_aton(ip)
		if len(ip.split('.')) == 4:
			ip = ip	
		else:
			sys.exit("Input does not consist of 4 octets!")
	except (socket.error):
		try:
			resolved_domain = socket.gethostbyname(ip)
			ip = resolved_domain
		except (socket.gaierror):
			sys.exit("Cannot resolve input")
	except (TypeError):
		sys.exit("Use argument -h for help")
	isonlist = False
	with open('./blacklists', 'r') as f:
		L = [line.strip() for line in f]

	for dnsbls in L:
		try:
			if  socket.gethostbyname("%s.%s" % (ip_reversed(ip), dnsbls)).startswith("127"):
				isonlist = True
		except (socket.gaierror):
			pass
	return isonlist
		
