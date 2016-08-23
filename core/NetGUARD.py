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
import time

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
	try:
        	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        	return socket.inet_ntoa(fcntl.ioctl(
        		s.fileno(),
        	        0x8915,
        	        struct.pack('256s', interface[:15])
        	)[20:24])
	except:
		print "[!] Set a valid interface on the configuration file."
		exit(0)
        # Function to get given interface MAC address
def get_mymac(interface):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        	info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', interface[:15]))
        	return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
	except:
		print "[!] Set a valid interface on the configuration file."
		exit(0)

	# Guardian Class
class NetGUARD(object):


	name = "Network Guardian"
	desc = "Defend host, give warnings to sysadmin and log to txt file."
	version = "0.8"

		# Initialize, create NetGUARD global variables and parse config file
	def __init__(self):


			# Config File
		os.path.abspath("config/NetGUARD.cfg")
                self.config = ConfigParser.ConfigParser()
                self.config.read("config/netguard.cfg")

			# Call Jarvis
		self.Jarvis = Jarvis()

			# Log file
		os.path.abspath("log/NetGUARD.log")

			# Jail
		self.jail = []

		try:
				# Network Interface from config
			self.interface = self.configmap("NetworkSettings")['interface']

				# Gateway IP address from config
			self.gateway_ip = self.configmap("NetworkSettings")['gateway_ip']

				# Gateway MAC address from config
			self.gateway_mac = self.configmap("NetworkSettings")['gateway_mac']

		except Exception as e:
			print "[-] Check your config file in NetGUARD/config/netguard.cfg"
			print "[!] Exception caught: ".format(e)
			exit(0)

			# My Network Interface MAC_Address
		self.mymac = get_mymac(self.interface)

			# My LAN IP Address
		self.myip = get_myip(self.interface)

			# If we are ARP spoofing status
		self.myspoof_status = False

			# If someone is ARP spoofing status
		self.spoof_status = False

			# ICMP request for this host - DDoS avoid.
		self.icmp_count = 0
			# Network ICMP sources in 5s
		self.icmpsenders = {}


			# TCP != from gateway connections - DDoS avoid.
		self.tcp_count = 0
			# Network UDP sources in 5s
		self.tcpsenders = {}

			# UDP != from gateway connections - DDoS avoid.
		self.udp_count = 0
			# Network UDP sources in 5s
		self.udpsenders = {}

			# SSH client attempts and brute status
		self.ssh_count = 0
		self.ssh_brute = False

			# MySQL client attempts and brute status
		self.sql_count = 0
		self.sql_brute = False

			# FTP client attempts and brute status
		self.ftp_count = 0
		self.ftp_brute = False

			# Time variables
		self.start_time = time.time()
		self.current_time = 0

		#ICMP time auxiliary
		self.itt = 0
		self.itt2 = 0

		#TCP time auxiliary
		self.ttt = 0
		self.ttt2 = 0

		#UDP time auxiliary
		self.utt = 0
		self.utt2 = 0

		#SSH time auxiliary
		self.sst = 0
		self.sst2 = 0

		#SQL time auxiliary
		self.sqt = 0
		self.sqt2 = 0

		#FTP time auxiliary
		self.ftt = 0
		self.ftt2 = 0

		# Configuration file mapping
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
			mac_dst = str(p[Ether].dst)
				# Media Acess Control source
			mac_src = str(p[Ether].src)


			# ARP Layer Protection
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
						self.Jarvis.Say("The gateway has returned to the original mac.")
						self.log("Gateway returned to original mac address.")
						self.spoof_status = False
					if self.myspoof_status == True:
						self.Jarvis.Say("You stopped to arp spoof the gateway sir.")
						self.log("This host stop to arp spoof the gateway. \n")
						self.myspoof_status = False
					return

					# If the op is: gateway is at and the hardware source diverges from original gateway MAC.
				if protocol_src == self.gateway_ip and hardware_src != self.gateway_mac:

						# If the person that are doing the ARP spoof is me."
					if hardware_src == self.mymac:


						if self.myspoof_status == False:
							self.Jarvis.Say("You are arp spoofing the gateway sir.")

								# Log
							self.log("This host start to arp spoof the gateway. \n")

								# Status
							self.myspoof_status = True

						else:
							return

						# If the person is not you
					else:
						if self.spoof_status == False:

							for i in range(0,3):
								self.Jarvis.Say("the mac {} is trying to arp spoof the network.".format(hardware_src.replace(":"," ")))
								#os.system("iptables -A INPUT -m mac --mac-source {} -j REJECT".format(hardware_src))
								time.sleep(2)

								# Log
							self.log("{} are trying to arp spoof the network. \n".format(hardware_src))

								# Status
							self.spoof_status = True

						else:
							return


                        # IP Layer Protection
                if p.haslayer(IP):
			ip_src = str(p[IP].src)
			ip_dst = str(p[IP].dst)
			ip_chk = p[IP].chksum
			ip_len = p[IP].len

				#DDoS ICMP Layer Protection
			if p.haslayer(ICMP):
				type = p[ICMP].type
				if ip_src != self.myip and ip_dst == self.myip and type == 8:
					if ip_dst not in self.icmpsenders:
							# Append new ICMP sender on network
						self.icmpsenders.update({ip_src: self.tcp_count})
					self.icmp_count += 1

					# First time value from 5s delay
				if self.icmp_count == 1:
					self.itt = time.time()
				else:
					self.itt2 = time.time()

				for ip,count in self.icmpsenders.iteritems():

					if count > 500 and ip not in self.jail:
						self.Jarvis.Say("The IP address {} is performing a ICMP denial of service attack against this host.".format(ip.replace("."," ")))
						self.log("IP - {}/MAC - {} start to perform a ICMP denial of service attack against this host.".format(ip,mac_dst))
						os.system("iptables -A INPUT -p icmp -s {} -j DROP".format(ip,str(dport)))
						self.Jarvis.Say("Raising the packet shield for the attacker")
						self.jail.append(ip)

				interval = self.itt2 - self.itt
				if interval >= 5:
					self.icmp_count = 0
					self.icmpsenders.clear()

				# DDoS TCP Layer Protection
			if p.haslayer(TCP):
	                        sport = p[TCP].sport
	                        dport = p[TCP].dport
				if ip_src != self.gateway_ip and ip_src != self.myip and ip_dst == self.myip:
					if ip_dst not in self.tcpsenders:
							# Append new TCP sender on network
						self.tcpsenders.update({ip_src: self.tcp_count})
					self.tcp_count += 1

					# First time value from 5s delay
				if self.tcp_count == 1:
				        self.ttt = time.time()
                                else:
						# Other time values from 5s delay
                                	self.ttt2 = time.time()

				for ip,count in self.tcpsenders.iteritems():

					if count > 500 and ip not in self.jail:
        	                                self.Jarvis.Say("The IP address {} is performing a TCP denial of service attack against this host.".format(ip.replace("."," ")))
               		                        self.log("IP - {}/MAC - {} start to perform a TCP denial of service attack against this host.".format(ip,mac_dst))
                                        	os.system("iptables -A INPUT -p tcp -s {} -j DROP".format(ip,str(dport)))
                                        	self.Jarvis.Say("Raising the packet shield for the attacker")
						self.log("Raising the packet shield for the attacker")
						self.jail.append(ip)

				interval = self.ttt2 - self.ttt
                                if interval >= 5:
					self.tcp_count = 0
					self.tcpsenders.clear()

                                # DDoS UDP Layer Protection
                        if p.haslayer(UDP):
                                sport = p[UDP].sport

                                if ip_src != self.gateway_ip and ip_src != self.myip and ip_dst == self.myip:
					if ip_dst not in self.udpsenders:
						self.udpsenders.update({ip_src: self.udp_count})
                                        self.udp_count += 1

                                if self.tcp_count == 1:
                                        self.utt = time.time()
                                else:
                                        self.utt2 = time.time()

				for ip,count in self.udpsenders.iteritems():

                                	if count > 500 and ip not in self.jail:
                                        	self.Jarvis.Say("The IP address {} is performing a UDP denial of service attack against this host.".format(ip_src.replace("."," ")))
                                        	self.log("IP - {}/MAC - {} start to perform a UDP denial of service attack against this host.".format(ip_src,mac_dst))
                                        	os.system("iptables -A INPUT -p udp -s {} -j DROP".format(ip_src,str(dport)))
                                        	self.Jarvis.Say("Raising the packet shield for the attacker")
                                        	self.log("Raising the packet shield for the attacker")
						self.jail.append(ip)

                                interval = self.utt2 - self.utt
                                if interval >= 5:
                                	self.udp_count = 0
					self.udpsenders.clear()




				# Brute-Force TCP Layer Protection
			if p.haslayer(TCP) and p.haslayer(Raw):
	                	flags = {'F':'FIN','S':'SYN','R':'RST','P':'PSH','A':'ACK','U':'URG','E':'ECE','C':'CWR'}
	                        dport = p[TCP].dport
	                        sport = p[TCP].sport
	                        ack = p[TCP].ack
	                        seq = p[TCP].seq
	                        preflag = [flags[x] for x in p.sprintf('%TCP.flags%')]
	                        flag = "/".join(preflag)
	                        chksum = str(p[TCP].chksum)
	                        load = p[Raw].load

					# FTP Protection
				if sport == 21 and "530" in load and ip_src == self.myip:

                                        if self.ftp_brute == False:
                                                self.Jarvis.Say("The IP address {} tried to connect with the FTP server with a wrong password.".format(ip_dst.replace("."," ")))
                                                self.log("IP - {}/MAC - {} tried to connect with the FTP server with a wrong password.".format(ip_dst,mac_dst))

                                        self.ftp_count +=1

                                        if self.ftp_count == 1:
                                                        # Live minutes
                                                self.ftt = time.time()
                                        else:
                                                self.ftt2 = time.time()

                                                # If 4 ftp_client packets and 4º count time - 1º count time >= 1
                                        if self.ftp_count >= 4:

                                                interval = self.ftt2 - self.ftt
                                                if interval >= 360:
                                                        self.ftp_count = 0
                                                else:
                                                        self.ftp_brute = True
                                                        os.system("iptables -A INPUT -p tcp -s {} --dport {} -j REJECT".format(ip_dst,str(sport)))
                                                        self.Jarvis.Say("The IP {} is brute forcing the FTP server.".format(ip_dst.replace("."," ")))
                                                        self.Jarvis.Say("Raising the packet shield for the attacker")

                                                                # Log
                                                        self.log("! IP - {}/MAC - {} is brute forcing the FTP server.".format(ip_dst,mac_dst))
                                                        self.log("Raising the packet shield for the attacker")

                                                                # Status
                                                        self.ftp_count = 0



					# MySQL Protection
				if sport == 3306 and "denied" in load and ip_src == self.myip:

					if self.sql_brute == False:
						self.Jarvis.Say("The IP address {} tried to connect with the SQL server with a wrong password.".format(ip_dst.replace("."," ")))
						self.log("IP - {}/MAC - {} tried to connect with the SQL server with a wrong password.".format(ip_dst,mac_dst))

                                        self.sql_count +=1

                                        if self.sql_count == 1:
                                                        # Live minutes
                                                self.sqt = time.time()
                                        else:
                                                self.sqt2 = time.time()

                                                # If 4 sql_client packets and 4º count time - 1º count time >= 1
                                        if self.sql_count >= 4:

                                                interval = self.sqt2 - self.sqt
                                                if interval >= 360:
                                                        self.sql_count = 0
                                                else:
                                                        self.sql_brute = True
                                                        os.system("iptables -A INPUT -p tcp -s {} --dport {} -j REJECT".format(ip_dst,str(sport)))
                                                        self.Jarvis.Say("The IP {} is brute forcing the SQL server.".format(ip_dst.replace("."," ")))
                                                        self.Jarvis.Say("Raising the packet shield for the attacker")

                                                                # Log
                                                        self.log("! IP - {}/MAC - {} is brute forcing the SQL server.".format(ip_dst,mac_dst))
                                                        self.log("Raising the packet shield for the attacker")

                                                                # Status
                                                        self.sql_count = 0


					# SSH Protection
				if "SSH" in load and ip_src != self.myip and ip_dst == self.myip:

					if self.ssh_brute == False:
						self.Jarvis.Say("The IP address {} open a socket with the SSH server.".format(ip_dst.replace("."," ")))
						self.log("IP - {}/MAC - {} open a socket with the SSH server.".format(ip_src,mac_src))

					self.ssh_count +=1

					if self.ssh_count == 1:
							# Live minutes
						self.sst = time.time()
					else:
						self.sst2 = time.time()

						# If 4 ssh_client packets and 4º count time - 1º count time >= 1
					if self.ssh_count >= 3:

						interval = self.sst2 - self.sst
						if interval >= 360:
							self.ssh_count = 0
							self.sst = 0
						else:
							self.ssh_brute = True
							os.system("iptables -A INPUT -p tcp -s {} --dport {} -j REJECT".format(ip_src,str(dport)))
							self.Jarvis.Say("The IP {} is brute forcing the SSH server.".format(ip_dst.replace("."," ")))
							self.Jarvis.Say("Raising the packet shield for the attacker")

								# Log
							self.log("! IP - {}/MAC - {} is brute forcing the SSH server.".format(ip_src,mac_src))
							self.log("Raising the packet shield for the attacker")

								# Status
							self.ssh_count = 0
							self.sst = 0



		# Logger
	def log(self, message):
		file = open("log/NetGUARD.log","a+")
		file.write("\n")
		time = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
		file.write(time + ": ")
		file.write(message)
		file.close()


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
			self.log("Exception: {}".format(e))


		# Start the sniffer as subprocess.
	def backgroundstart(self):
		try:
			with open("log/NetGUARD.log","a+") as stdout:
				self.p = subprocess.Popen(["python core/NetGUARD.py"], shell=True, stdout=stdout, stderr=stdout)
			self.log("NetGUARD in background started.")
			return
		except Exception as e:
			self.Jarvis.Say("Problem starting the network monitor in background")
			self.log("Problem starting NetGUARD in background")


if __name__ == "__main__":

	netguard = NetGUARD()
	netguard.start()
