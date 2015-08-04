#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
sniff packets from interface en1 using python module scapy (2.3.1)
generate color point matrix in the terminal window depending on packet port number
v0.1
By Sam Neurohack
LICENCE : BY NC
'''

from blessings import Terminal
from time import sleep

import collections

import argparse

import types
import random
from scapy.all import *


term = Terminal()

#print len(colornodes)
#sleep(5)

parser = argparse.ArgumentParser(description="A Scanner Interface Darkly")
parser.add_argument("interface",help="interface to scan")
parser.add_argument("-x","--xcol",help="number of columns (8 by default)",type=int)
parser.add_argument("-y","--ycol",help="number of rows (8 by default)",type=int)
parser.add_argument("-f","--filter",help="tcpdump filter")
parser.add_argument("-c","--color",help="number of color",type=int)
parser.add_argument("-d","--display",help="type of side display",choices=["colors", "ports"])
parser.add_argument("-epi","--ephemeralportmin",help="ephemeral port min to exclude (32768 by default), set to 65536 to include all ports",type=int)
parser.add_argument("-epa","--ephemeralportmax",help="ephemeral port max to exclude (61000 by default)",type=int)
args = parser.parse_args()

if args.xcol:
	xmax=args.xcol
else:
	xmax=8

if args.ycol:
	ymax=args.ycol
else:
	ymax=8

if args.color:
	nbcolor=args.color
else:
	nbcolor=15

if args.display:
	sidedisplay=args.display
else:
	sidedisplay="ports"

if args.ephemeralportmin:
	ephemeralportmin = args.ephemeralportmin
else:
	ephemeralportmin = 32768

if args.ephemeralportmax:
	ephemeralportmax = args.ephemeralportmax
else:
	ephemeralportmax = 61000

ysteps = 3
yposinit=0
ypos = yposinit

xsteps = 8
xposinit = 0
xpos = xposinit

colornodes = [0] * xmax*ymax

colornumber = 0
colornode = 0

recentports = [0] * nbcolor
#portavg = [0] * nbcolor
freeport = 0

ports = collections.Counter()


def sendled(zzzport):
	global colornodes, colornode, nbcolor
	global xsteps, xmax, xposinit, xpos
	global ysteps, ymax, yposinit, ypos
	global args, recentports, freeport
	
	if not zzzport in recentports:
		recentports[freeport] = zzzport
		freeport += 1
		if freeport >= nbcolor:
			freeport = 0

#	if zzzport in ports:
	ports[zzzport]+=1
#	else:
#		ports[zzzport]=1

#	print colornode
	colornodes[colornode] = zzzport % nbcolor
	
#	with term.fullscreen():
		
#	colornumber = 0
	with term.location(0,0):
		print term.on_black('pos:*' + ('0' + str(colornode))[-2:] + '')

	with term.location(0,1):
		print term.on_red('c[' + ('0' + str(colornumber))[-2:] + ']' + ('0' + str(colornodes[colornumber]))[-2:] + '')

	with term.location(0,2):
		print term.on_blue('c[' + ('0' + str(colornode))[-2:] + ']' + ('0' + str(colornodes[colornode]))[-2:] + '')

	with term.location(0,3):
		print term.on_color(zzzport % nbcolor) + 'p:' + ('0000' + str(zzzport))[-5:] + ''


	with term.location(0,4):
		print term.on_yellow('y:' + hex(ypos)[-1:] + ',x:' + hex(xpos)[-1:])

	with term.location(0,6):
		print term.on_color(8)+'i:'+('     '+str(args.interface))[-5:]
	
	for col in range(0,nbcolor):
		with term.location(0,8+col):
			if sidedisplay == "ports":
#				print term.on_color(recentports[col]%nbcolor)+ 'p:' +('0000' + str(recentports[col]))[-5:]
				if col < len(ports.most_common(nbcolor)):
					print term.on_color(ports.most_common(nbcolor)[col][0]%nbcolor)+ 'p:' +('0000' + str(ports.most_common(nbcolor)[col][0]))[-5:]
			else:
				print term.on_color(col)+('0'+str(col))[-2:]

	with term.location((xpos+1)*xsteps, ypos*ysteps):
		print term.on_color(colornodes[colornode]) + '   '
	with term.location((xpos+1)*xsteps, (ypos*ysteps)+1):
		print term.on_color(colornodes[colornode]) + '   '

	colornode += 1
#	colornumber += 1
	xpos += 1

	if xpos >= xmax:
		xpos=xposinit
		ypos += 1
		if ypos >= ymax:
			ypos=yposinit
			colornode = 0



def print_summary(pkt):
    if IP in pkt:
        ip_src=pkt[IP].src
        ip_dst=pkt[IP].dst
        
        
    	if TCP in pkt:
        	tcp_sport=pkt[TCP].sport
        	tcp_dport=pkt[TCP].dport

        	if not (ephemeralportmin < tcp_sport < ephemeralportmax):
#        		print " IP src " + str(ip_src) + " TCP sport " + str(tcp_sport) 
        		sendled(tcp_sport)
        		if not (ephemeralportmin < tcp_dport < ephemeralportmax):
#	        		print " IP dst " + str(ip_dst) + " TCP dport " + str(tcp_dport)
        			sendled(tcp_dport)
		else:
        		if not (ephemeralportmin < tcp_dport < ephemeralportmax):
#		        	print " IP dst " + str(ip_dst) + " TCP dport " + str(tcp_dport)
        			sendled(tcp_dport)
			else:
				sendled(tcp_sport)
				sendled(tcp_dport)

        if UDP in pkt:
        	udp_sport=pkt[UDP].sport
        	udp_dport=pkt[UDP].dport

        	if not (ephemeralportmin < udp_sport < ephemeralportmax):
#        		print " IP src " + str(ip_src) + " UDP sport " + str(udp_sport) 
        		sendled(udp_sport)
        		if not (ephemeralportmin < udp_dport < ephemeralportmax):
#        			print " IP dst " + str(ip_dst) + " UDP dport " + str(udp_dport)
        			sendled(udp_dport)
		else:
        		if not (ephemeralportmin < udp_dport < ephemeralportmax):
#        			print " IP dst " + str(ip_dst) + " UDP dport " + str(udp_dport)
        			sendled(udp_dport)
			else:
				sendled(udp_sport)
				sendled(udp_dport)


#	if ARP in pkt and pkt[ARP].op in (1,2):
	if ARP in pkt: 
#		print " ARP"
		sendled(67676)

	if ICMP in pkt:
#		print " ICMP"
		sendled(68686)


def handle_error(self,request,client_address):		# All callbacks
    pass



with term.fullscreen():

	print term.on_black('Ok:'+args.interface)

	sleep(2)

	print(term.clear())

	#sniff(iface=args.interface, prn=print_summary, store=0,filter="not (host 192.168.1.42 and not port 22)")
	sniff(iface=args.interface, prn=print_summary, store=0,filter=args.filter)




time.sleep(2)

print term.normal

term.exit_fullscreen

