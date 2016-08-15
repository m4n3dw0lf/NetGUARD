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

	# disable warnings from scapy
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

	# core libs
import os
from jarvis import Jarvis
from datetime import datetime

	# background running
import subprocess

	# getmac and getip
import socket
import fcntl
import struct

	# parse config file
import ConfigParser


	# Function to get given interface IP address
def get_myip(interface):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
        	s.fileno(),
                0x8915,
                struct.pack('256s', interface[:15])
        )[20:24])


        # Function to get given interface MAC address
def get_mymac(interface):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', interface[:15]))
        return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]



class NetGUARD(object):


	name = "Network Guardian"
	desc = "Defend host, give warnings to sysadmin and log to txt file."
	version = "0.3"


	def __init__(self):


			# Config File
                self.config = ConfigParser.ConfigParser()
                self.config.read("config/netguard.cfg")

			# Call Jarvis
		self.Jarvis = Jarvis()

			# Log file
		self.file = open("log/NetGUARD.log","a+")

		try:
				# Network Interface
			self.interface = self.configmap("NetworkSettings")['interface']

				# Gateway IP address
			self.gateway_ip = self.configmap("NetworkSettings")['gateway_ip']

				# Gateway MAC address
			self.gateway_mac = self.configmap("NetworkSettings")['gateway_mac']

		except Exception as e:
			print "[-] Check your config file in NetGUARD/config/netguard.cfg"
			print "[!] Exception caught: ".format(e)
			exit(0)

			# My Network Interface MAC_Address
		self.mymac = get_mymac(self.interface)

			# My LAN IP Address
		self.myip = get_myip(self.interface)

			# If we are ARP spoofing
		self.myspoof_status = False

			# If someone is ARP spoofing
		self.spoof_status = False


	def configmap(self, section):
		dict = {}
		options = self.config.options(section)
		for option in options:
			try:
				dict[option] = self.config.get(section,option)
				if dict[option] == -1:
					DebugPrint("[!] Skip: {}".format(option))
			except:
				print "[!] Exception on: %s".format(s)
				dict[option] = None
		return dict


		# Main routine
	def main(self, p):

			# Ethernet Frame
		if p.haslayer(Ether):
				# Media Access Control destination
			mac_dst = p[Ether].dst
				# Media Acess Control source
			mac_src = p[Ether].src

			# ARP Layer
		if p.haslayer(ARP):

				# is-at
			if p[ARP].op == 2:
					# Sender Hardware Address
				hardware_src = p[ARP].hwsrc
					# Sender Protocol Address
				protocol_src = p[ARP].psrc
					# Target Hardware Address
				hardware_dst = p[ARP].hwdst
					# Target Protocol Address
				protocol_dst = p[ARP].pdst

					# If gateway ARP is-at is normal
				if protocol_src == self.gateway_ip and hardware_src == self.gateway_mac:
					if self.spoof_status == True:
						self.Jarvis.Say("The gateway has returned to the original MAC.")
						self.log("Gateway returned to original MAC address.")
						self.spoof_status = False
					if self.myspoof_status == True:
						self.Jarvis.Say("You stopped to arp spoof the gateway sir.")
						self.log("This host stop to ARP spoof the gateway. \n")
						self.myspoof_status = False
					return

					# If the op is: gateway is at and the hardware source diverges from original gateway MAC.
				if protocol_src == self.gateway_ip and hardware_src != self.gateway_mac:

						# If the person that are doing the ARP spoof is me."
					if hardware_src == self.mymac:


						if self.myspoof_status == False:
							self.Jarvis.Say("You are arp spoofing the gateway sir.")

								# Log
							self.log("This host start to ARP spoof the gateway. \n")

								# Status
							self.myspoof_status = True

						else:
							return

						# If the person is not you
					else:
						if self.spoof_status == False:

							for i in range(0,3):
								self.Jarvis.Say("Someone is trying to ARP spoof the network.")
								time.sleep(2)

								# Log
							self.log("{} are trying to ARP spoof the gateway. \n".format(hardware_src))

								# Status
							self.spoof_status = True

						else:
							return

		# Logger
	def log(self, message):
		self.file.write("\n")
		time = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
		self.file.write(time + ": ")
		self.file.write(message)


		# Start
	def start(self):
		try:
			pid = os.getpid()
			self.Jarvis.Say("Network guardian initialized on process {}.".format(pid))
			self.log("NetGUARD started")

				# Set static ARP with the gateway.
			self.Jarvis.Say("Setting static arp with gateway.")
			os.system("arp -s {} {}".format(self.gateway_ip, self.gateway_mac))
			self.log("Static ARP set with gateway.")

			self.Jarvis.Say("I will warn you if i find any threat")


				# Start the sniffer.
			p = sniff(iface=self.interface, prn = self.main)
                        time = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
                        wrpcap("NetGUARD_{}.pcap".format(time),p)

		except Exception as e:
			self.Jarvis.Say("Problem starting the network monitor")
			self.log("Problem starting the network monitor")


		# Start the sniffer as subprocess.
	def backgroundstart(self):
		try:
			with open("log/NetGUARD.log","a+") as stdout:
				self.p = subprocess.Popen(["python core/main.py"], shell=True, stdout=stdout, stderr=stdout)
			self.log("NetGUARD in background started.")
			return
		except Exception as e:
			self.Jarvis.Say("Problem starting the network monitor in background")
			self.log("Problem starting NetGUARD in background")


if __name__ == "__main__":

	netguard = NetGUARD()
	netguard.start()
