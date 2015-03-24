#WireLess Network Sniffer
#Used Socket Programming to create a network sniffer from scrach to analyze the  raw packets of the system, the program sniffes the packets and at the same time create the capture file of the analyzed packets.
#Supports Multiple Protocols including TCP/IP,OSPF,BGP,ARP etc.
#Program does contain a number of bugs since i'm not a PRO in coding :) and the program is in its BETA stage
#Since the program directly interacts with the Kernal for sniffing the raw packet you need be root to run the program
#Feel free to contribute to improve the functionality 
'''
Copyright (C) 2015 Abhishek Pratap Singh
This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
'''    

#! /usr/bin/env python

import signal
import socket
import struct
import binascii

def left(x,y): 
	print "\n"+"Program Closed!!"
	exit()
signal.signal(2, left)

rawSocket=socket.socket(socket.PF_PACKET,socket.SOCK_RAW, socket.htons(0x0003))

count = 0
while True:
#########################Parse the packet for different Protocols##########################
 try:        	
	packet = rawSocket.recvfrom(65535)
	count = count + 1
	###########ETHERNET HEADER#########################

	ethernetHeader = packet[0][0:14]
 	eth_hdr   = struct.unpack("!6s6s2s", ethernetHeader)
 	sourceMAC = binascii.hexlify(eth_hdr[0])
 	destiMAC  = binascii.hexlify(eth_hdr[1])
 	protocol  = binascii.hexlify(eth_hdr[2]) 


	############Internet Protocol Header###############

	ipHeader   =     packet[0][14:34]
	ip_hdr     =     struct.unpack("!BBHHBBBBH4s4s",ipHeader)
	versionIHL =     ip_hdr[0]
	version    =     versionIHL >> 4     ##Divide versionIHL by 2^4
	IdentificationFragment = ip_hdr[3]
	TTL        =     ip_hdr[6]
	Protocol   =     ip_hdr[7]

  if Protocol == 1:
		      Protocol = 'ICMPv4'
	elif Protocol == 2:
		      Protocol = 'IGMP'
	elif Protocol == 4:
		      Protocol = 'IPv4'
	elif Protocol == 6:
		      Protocol = 'TCP'
	elif Protocol == 8:
		      Protocol = 'EGP'
	elif Protocol == 17:
		      Protocol = 'UDP'
	elif Protocol == 41:
		      Protocol = 'IPv6'
	elif Protocol == 50:
		      Protocol = 'IPSec ESP Header'
	elif Protocol == 51:
		      Protocol = 'IPSec AH Header'
	elif Protocol == 89:
		      Protocol = 'OSPF'
	elif Protocol == 132:
		      Protocol = 'SCTP'
	elif Protocol == 3:
          Protocol = '802.1X Authntication'
  elif Protocol == 5:
          Protocol = 'Internet Stream Protocol'
  elif Protocol == 9:
          Protocol = 'EGP'
  elif Protocol == 19:
          Protocol = 'DCN Measurement Subsystems'
  elif Protocol == 21:
          Protocol = 'Packet Radio Measurement'
  elif Protocol == 27:
          Protocol = 'Reliable Datagram Protocol'
  elif Protocol == 28:
          Protocol = 'Internet Reliable Transaction Protocol'
  elif Protocol == 30:
          Protocol = 'Bulk Data Transfer Protocol'
  elif Protocol == 33:
          Protocol = 'Datagram Congestion Control Protocol'
  elif Protocol == 35:
          Protocol = 'Inter-Domain Policy Routing Protocol'
  elif Protocol == 37:
          Protocol = 'Datagram Delivery Protocol'
  elif Protocol == 39:
          Protocol = 'TP++ Transport Protocol'
  elif Protocol == 40:
          Protocol = 'IL Transport Protocol'
  elif Protocol == 41:
          Protocol = 'IPv6 Encapsulation'
  elif Protocol == 42:
          Protocol = 'Source Demand Routing Protocol'
  elif Protocol == 43:
          Protocol = 'Routing Header for IPv6'
  elif Protocol == 44:
          Protocol = 'Fragment Header for IPv6'
  elif Protocol == 46:
          Protocol = 'Resource Reservation Protocol'
  elif Protocol == 47:
          Protocol = 'Generic Routing Encapsulation'
  elif Protocol == 48:
          Protocol = 'Mobile Host Routing Protocol'
  elif Protocol == 50:
          Protocol = 'Encapsulating Security Payload'
  elif Protocol == 51:
          Protocol = 'Authentication Header'
  elif Protocol == 52:
          Protocol = 'Integrated Net Layer Security Protocol'
  elif Protocol == 54:
          Protocol = 'NBMA Address Resolution Protocol'
  elif Protocol == 55:
          Protocol = 'IP Mobility'
  elif Protocol == 56:
          Protocol = 'Transport Layer Security Protocol'
  elif Protocol == 57:
          Protocol = 'Simple Key-Management for Internet Protocol'
  elif Protocol == 58:
          Protocol = 'ICMP for IPv6'
  elif Protocol == 61:
          Protocol = 'Any host internal protocol'
  elif Protocol == 63:
          Protocol = 'Any local network'
  elif Protocol == 84:
          Protocol = 'Internet Protocol Traffic Manager'
  elif Protocol == 86:
          Protocol = 'Dissimilar Gateway Protocol'
  elif Protocol == 92:
          Protocol = 'Multicast Transport Protocol'
  elif Protocol == 93:
          Protocol = 'AX.25'
  elif Protocol == 94:
          Protocol = 'IP-within-IP Encapsulation Protocol'
  elif Protocol == 95:
          Protocol = 'Mobile Internetworking Control Protocol'
  elif Protocol == 97:
          Protocol = 'Ethernet-within-IP Encapsulation'
  elif Protocol == 98:
          Protocol = 'Encapsulation Header'
  elif Protocol == 99:
          Protocol = 'Any private encryption scheme'
  elif Protocol == 100:
          Protocol = 'GMTP'
  elif Protocol == 102:
          Protocol = 'PNNI over IP'
  elif Protocol == 103:
          Protocol = 'Protocol Independent Multicast'
  elif Protocol == 106:
          Protocol = 'QNX'
  elif Protocol == 107:
          Protocol = 'Active Networks'
  elif Protocol == 108:
          Protocol = 'IP Payload Compression Protocol'
  elif Protocol == 113:
          Protocol = 'PGM Reliable Transport Protocol'
  elif Protocol == 114:
          Protocol = 'Any 0-hop protocol'
  elif Protocol == 115:
          Protocol = 'Layer Two Tunneling Protocol Version 3'
  elif Protocol == 116:
          Protocol = 'D-II Data Exchange (DDX)'
  elif Protocol == 117:
          Protocol = 'Interactive Agent Transfer Protocol'
  elif Protocol == 118:
          Protocol = 'Schedule Transfer Protocol'
  elif Protocol == 120:
          Protocol = 'Universal Transport Interface Protocol'
  elif Protocol == 121:
          Protocol = 'Simple Message Protocol'
  elif Protocol == 122:
          Protocol = 'Simple Multicast Protocol'
  elif Protocol == 123:
          Protocol = 'Performance Transparency Protocol'
  elif Protocol == 124:
          Protocol = 'Intermediate System to Intermediate System (IS-IS) Protocol over IPv4'
  elif Protocol == 125:
          Protocol = 'Flexible Intra-AS Routing Environment'
  elif Protocol == 126:
          Protocol = 'Combat Radio Transport Protocol'
  elif Protocol == 127:
          Protocol = 'Combat Radio User Datagram'
  elif Protocol == 128:
          Protocol = 'Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment'
  elif Protocol == 131:
          Protocol = 'Private IP Encapsulation within IP'
  elif Protocol == 132:
          Protocol = 'Stream Control Transmission Protocol'
  elif Protocol == 133:
          Protocol = 'Fibre Channel'
  elif Protocol == 134:
          Protocol = 'Reservation Protocol (RSVP) End-to-End Ignore'
  elif Protocol == 135:
          Protocol = 'Mobility Extension Header for IPv6'
  elif Protocol == 136:
          Protocol = 'Lightweight User Datagram Protocol'
  elif Protocol == 137:
          Protocol = 'Multiprotocol Label Switching Encapsulated in IP'
  elif Protocol == 138:
          Protocol = 'MANET Protocols'
  elif Protocol == 139:
          Protocol = 'Host Identity Protocol'
  elif Protocol == 140:
          Protocol = 'Site Multihoming by IPv6 Intermediation'
  elif Protocol == 141:
          Protocol = 'Wrapped Encapsulating Security Payload'
  elif Protocol == 142:
          Protocol = 'Robust Header Compression'

	HeaderChecksum =  (ip_hdr[8])
	SourceIP       =  socket.inet_ntoa(ip_hdr[9])
	DestinationIP  =  socket.inet_ntoa(ip_hdr[10])
	interface = packet[1][0]

#############################TCP Header###################################################
	
	tcpHeader  = packet[0][34:46]	
	tcp_hdr    = struct.unpack("!HHLL",tcpHeader)
	sourcePort = tcp_hdr[0]
	destiPort  = tcp_hdr[1]
	seqNumber  = tcp_hdr[2]
	ackNumber  = tcp_hdr[3]
	
#################################Data#####################################################

	data = packet[0][56:]
	if len(data) > 0:
		Data = data
##################Determines the protocol and Creates the Capture file#####################
 	
	if protocol == '0800':
	 print (" ##Interface" +'\n'+'   ' + 
	"  Interface: {}".format(interface) +'\n'+'\n'+'\t'+
	'##Ethernet Header' +'\n' +'\t'+'\t' +
	"Source MAC Address is: {}".format(sourceMAC) +'\n'+'\t'+'\t'+
	"Destiation MAC Address is: {}".format(destiMAC) +'\n'+'\t'+'\t'+
	"Protocol: {}".format(protocol) +'\n'+'\n'+'\t'+'\t'+
	'##IP Header'+'\n'+'\t'+'\t'+'\t'+
	"Version: {}".format(version)+'\n'+'\t'+'\t'+'\t'+
	"IdentificationFragment: {}".format(IdentificationFragment) +'\n'+'\t'+'\t'+'\t'+
	"TTL: {}".format(TTL) +'\n'+'\t'+'\t'+'\t'+
	"Protocol: {}".format(Protocol) +'\n'+'\t'+'\t'+'\t'+
	"HeaderChecksum: {}".format(HeaderChecksum) +'\n'+'\t'+'\t'+'\t'+
	"SourceIP: {}".format(SourceIP) +'\n'+'\t'+'\t'+'\t'+
	"DestinationIP: {}".format(DestinationIP) +'\n'+'\n'+'\t'+'\t'+'\t'+ 
	'##TCP Header'+'\n'+'\t'+'\t'+'\t'+'\t'+
	"Source Port: {}".format(sourcePort)+'\n'+'\t'+'\t'+'\t'+'\t'+
	"Destination Port: {}".format(destiPort)+'\n'+'\t'+'\t'+'\t'+'\t'+
	"Sequence Number: {}".format(seqNumber)+'\n'+'\t'+'\t'+'\t'+'\t'+
	"Acknowledgement Number: {}".format(ackNumber)+'\n'+'\t'+'\t'+'\t'+'\t'+
	"Data: {}".format(Data)+'\n'+'\n')	

###################################File Handling############################################
	 fh=open('InternetProtocol.txt','a+w') 

	 fh.write(str(str(count)+ 
	" ##Interface" +'\n'+'   '+
	"  Interface: {}".format(interface)+'\n'+'\n'+'\t'+
	'##Ethernet Header' +'\n' +'\t'+'\t' +
	"Source MAC Address is: {}".format(sourceMAC) +'\n'+'\t'+'\t'+	
	"Destiation MAC Address is: {}".format(destiMAC) +'\n'+'\t'+'\t'+
	"Protocol: {}".format(protocol) +'\n'+'\n'+'\t'+'\t'+
	'##IP Header'+'\n'+'\t'+'\t'+'\t'+
	"Version: {}".format(version) +'\n'+'\t'+'\t'+'\t'+
	"IdentificationFragment: {}".format(IdentificationFragment) +'\n'+'\t'+'\t'+'\t'+
	"TTL: {}".format(TTL) +'\n'+'\t'+'\t'+'\t'+
	"Protocol: {}".format(Protocol) +'\n'+'\t'+'\t'+'\t'+
	"HeaderChecksum: {}".format(HeaderChecksum) +'\n'+'\t'+'\t'+'\t'+
	"SourceIP: {}".format(SourceIP) +'\n'+'\t'+'\t'+'\t'+
	"DestinationIP: {}".format(DestinationIP) +'\n'+'\n'+'\t'+'\t'+'\t'+
	'##TCP Header'+'\n'+'\t'+'\t'+'\t'+'\t'+
	"Source Port: {}".format(sourcePort)+'\n'+'\t'+'\t'+'\t'+'\t'+
	"Destination Port: {}".format(destiPort)+'\n'+'\t'+'\t'+'\t'+'\t'+
	"Sequence Number: {}".format(seqNumber)+'\n'+'\t'+'\t'+'\t'+'\t'+
	"Acknowledgement Number: {}".format(ackNumber)+'\n'+'\t'+'\t'+'\t'+'\t'+
	"Data: {}".format(Data)+'\n'+'\n'))

	 fh.close()

 	elif protocol == '0806':
	 fh=open('ARPprotocol.txt','a+w')
	 fh.write(str(str(count)+ 
	" ##Interface" +'\n'+'   '+
	"  Interface: {}".format(interface) +'\n'+'\n'+'\t'+
	'##Ethernet Header'+'\n' +'\t'+'\t'+
	"Source MAC Address is: {}".format(sourceMAC) +'\n'+'\t'+'\t'+
	"Destiation MAC Address is: {}".format(destiMAC)+'\n'+'\t'+'\t'+
	"Protocol: {}".format(protocol) +'\n'+'\n'+'\t'+'\t'+
	'##IP Header'+'\n'+'\t'+'\t'+'\t'+ 
	"Version: {}".format(version) +'\n'+'\t'+'\t'+'\t'+
	"IdentificationFragment: {}".format(IdentificationFragment) +'\n'+'\t'+'\t'+'\t'+
	"TTL: {}".format(TTL) +'\n'+'\t'+'\t'+'\t'+
	"Protocol: {}".format(Protocol) +'\n'+'\t'+'\t'+'\t'+ 
	"HeaderChecksum: {}".format(HeaderChecksum) +'\n'+'\t'+'\t'+'\t'+ 
	"SourceIP: {}".format(SourceIP) +'\n'+'\t'+'\t'+'\t'+ 
	"DestinationIP: {}".format(DestinationIP) +'\n'+'\n'+'\t'+'\t'+'\t'+ 
	'##TCP Header'+'\n'+'\t'+'\t'+'\t'+'\t'+
	"Source Port: {}".format(sourcePort)+'\n'+'\t'+'\t'+'\t'+'\t'+
	"Destination Port: {}".format(destiPort)+'\n'+'\t'+'\t'+'\t'+'\t'+
	"Sequence Number: {}".format(seqNumber)+'\n'+'\t'+'\t'+'\t'+'\t'+
	"Acknowledgement Number: {}".format(ackNumber)+'\n'+'\t'+'\t'+'\t'+'\t'+
	"Data: {}".format(Data)+'\n'+'\n'))
        

	elif protocol == '0x0060':
	 fh.open("Loopback.txt", "a+w")
	 fh.write(str(str(count)+
        " ##Interface" +'\n'+'   '+
        "  Interface: {}".format(interface) +'\n'+'\n'+'\t'+
        '##Ethernet Header'+'\n' +'\t'+'\t'+
        "Source MAC Address is: {}".format(sourceMAC) +'\n'+'\t'+'\t'+
        "Destiation MAC Address is: {}".format(destiMAC)+'\n'+'\t'+'\t'+
        "Protocol: {}".format(protocol) +'\n'+'\n'+'\t'+'\t'+
        '##IP Header'+'\n'+'\t'+'\t'+'\t'+
        "Version: {}".format(version) +'\n'+'\t'+'\t'+'\t'+
        "IdentificationFragment: {}".format(IdentificationFragment) +'\n'+'\t'+'\t'+'\t'+
        "TTL: {}".format(TTL) +'\n'+'\t'+'\t'+'\t'+
        "Protocol: {}".format(Protocol) +'\n'+'\t'+'\t'+'\t'+
        "HeaderChecksum: {}".format(HeaderChecksum) +'\n'+'\t'+'\t'+'\t'+
        "SourceIP: {}".format(SourceIP) +'\n'+'\t'+'\t'+'\t'+
        "DestinationIP: {}".format(DestinationIP) +'\n'+'\n'+'\t'+'\t'+'\t'+
        '##TCP Header'+'\n'+'\t'+'\t'+'\t'+'\t'+
        "Source Port: {}".format(sourcePort)+'\n'+'\t'+'\t'+'\t'+'\t'+
        "Destination Port: {}".format(destiPort)+'\n'+'\t'+'\t'+'\t'+'\t'+
        "Sequence Number: {}".format(seqNumber)+'\n'+'\t'+'\t'+'\t'+'\t'+
        "Acknowledgement Number: {}".format(ackNumber)+'\n'+'\t'+'\t'+'\t'+'\t'+
        "Data: {}".format(Data)+'\n'+'\n'))
	 

	elif protocol == '0x86dd':
         fh.open("IPv6.txt", "a+w")
         fh.write(str(str(count)+
        " ##Interface" +'\n'+'   '+
        "  Interface: {}".format(interface) +'\n'+'\n'+'\t'+
        '##Ethernet Header'+'\n' +'\t'+'\t'+
        "Source MAC Address is: {}".format(sourceMAC) +'\n'+'\t'+'\t'+
        "Destiation MAC Address is: {}".format(destiMAC)+'\n'+'\t'+'\t'+
        "Protocol: {}".format(protocol) +'\n'+'\n'+'\t'+'\t'+
        '##IP Header'+'\n'+'\t'+'\t'+'\t'+
        "Version: {}".format(version) +'\n'+'\t'+'\t'+'\t'+
        "IdentificationFragment: {}".format(IdentificationFragment) +'\n'+'\t'+'\t'+'\t'+
        "TTL: {}".format(TTL) +'\n'+'\t'+'\t'+'\t'+
        "Protocol: {}".format(Protocol) +'\n'+'\t'+'\t'+'\t'+
        "HeaderChecksum: {}".format(HeaderChecksum) +'\n'+'\t'+'\t'+'\t'+
        "SourceIP: {}".format(SourceIP) +'\n'+'\t'+'\t'+'\t'+
        "DestinationIP: {}".format(DestinationIP) +'\n'+'\n'+'\t'+'\t'+'\t'+
        '##TCP Header'+'\n'+'\t'+'\t'+'\t'+'\t'+
        "Source Port: {}".format(sourcePort)+'\n'+'\t'+'\t'+'\t'+'\t'+
        "Destination Port: {}".format(destiPort)+'\n'+'\t'+'\t'+'\t'+'\t'+
        "Sequence Number: {}".format(seqNumber)+'\n'+'\t'+'\t'+'\t'+'\t'+
        "Acknowledgement Number: {}".format(ackNumber)+'\n'+'\t'+'\t'+'\t'+'\t'+
        "Data: {}".format(Data)+'\n'+'\n'))

	 fh.close()
	print "Packet Captured: {}".format(count)
 except struct.error:
	pass
