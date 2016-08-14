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


import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import os
from core.jarvis import Jarvis
from datetime import datetime
from modules.utils import *

class NetMON(object):

	name = "Network Monitor"
	desc = "Jarvis warnings to sysadmin and log to txt file."
	version = "0.1"

	def __init__(self):

			# Call Jarvis
		self.Jarvis = Jarvis()

			# Log file
		self.file = open("log/NetMONlog.txt","a+")

			# Network Interface
		self.interface = raw_input("[+] Enter the network interface: ")

			# Gateway IP address
		self.gateway_ip = raw_input("[+] Enter the gateway IP address: ")

			# Gateway MAC address
		self.gateway_mac = raw_input("[+] Enter the gateway MAC address: ")

			# My Network Interface MAC_Address
		self.mymac = get_mymac(self.interface)

			# My LAN IP Address
		self.myip = get_myip(self.interface)

			# If we are ARP spoofing
		self.myspoof_status = False

			# If someone is ARP spoofing
		self.spoof_status = False

		# Deauthenticate someone from LAN
	#def kick(self, mac):
		#self.log(" We deauthenticate the MAC: {} and kick him out of the LAN".format(mac))

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
						self.spoof_status = False
					if self.myspoof_status == True:
						self.Jarvis.Say("We stop to arp spoof the gateway sir.")
						self.myspoof_status = False
					return

					# If the op is: gateway is at and the hardware source diverges from original gateway MAC.
				if protocol_src == self.gateway_ip and hardware_src != self.gateway_mac:

						# If the person that are doing the ARP spoof is me."
					if hardware_src == self.mymac:


						if self.myspoof_status == False:
							self.Jarvis.Say("We are arp spoofing the gateway sir.")

								# Log
							self.log("This host start to ARP spoof the gateway. \n")

								# Status
							self.myspoof_status = True

						else:
							return

						# Else
					else:
						self.spoof_status = True
						self.Jarvis.Say("Someone that is not us is trying to ARP spoof the gateway.")
						self.Jarvis.Say("I will kick him out of the lan sir.")

							#Deauthenticate attacker from LAN.
						#self.kick(hardware_src)

							# Log
						self.log("{} are trying to ARP spoof the gateway. \n")


		# Logger
	def log(self, message):
		self.file.write("\n")
		time = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
		self.file.write(time + ": ")
		self.file.write(message)

		# Start the sniffer
	def start(self):
		try:
			p = sniff(iface=self.interface, prn = self.main)
			self.log("NetMON started")
		except Exception as e:
			self.Jarvis.Say("Problem starting the network monitor")
			self.log("Problem starting the network monitor")

		# Start the sniffer as subprocess
	def backgroundstart(self):
		try:
			self.p = subprocess.Popen(["python netmon.py","NetMON"], shell=False)
			self.log("NetMON in background started.")
		except Exception as e:
			self.Jarvis.Say("Problem starting the network monitor in background")
			self.log("Problem starting NetMON in background")

if __name__ == "__main__":

	netmon = NetMON()
	netmon.start()
