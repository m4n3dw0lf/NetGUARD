#!/usr/bin/env python2.7
#coding=UTF-8

# Copyright (c) 2016 Angelo Moura
#
# NetGUARD is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA

import os,sys
from core.NetGUARD import NetGUARD


path = os.path.abspath(os.path.dirname(sys.argv[0]))
netguard = NetGUARD()

version = "1.1"
if os.geteuid() != 0:
	sys.exit("[-] Should be run as root.")


def print_help(version):
	print " [*] NetGUARD v{}".format(version)
	print
	print " --verbose || -v           Start NetGUARD verbosely."
	print " --stop || -s		  Stop NetGUARD."
	print " --help || -h		  Print this help message."


if __name__ == "__main__":
	try:
		if sys.argv[1] == "--verbose" or sys.argv[1] == "-v":
			netguard.backgroundstart()
			os.system("tail -f {}/log/NetGUARD.log".format(path))
		elif sys.argv[1] == "--stop" or sys.argv[1] == "-s":
				# KILL SIGINT 'CTRL + C' to generate pcap
			print "[!] NetGUARD finalized."
			os.system("killall python -s 2")
		elif sys.argv[1] == "--help" or sys.argv[1] == "-h":
			print_help(version)

	except IndexError:
		netguard.backgroundstart()

	except Exception as e:
		print "[!] Exception caught: {}".format(e)
