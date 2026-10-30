#!/usr/bin/env python3
# send.py <src> <dst> <tag>: one UDP packet via the routing table (scapy L3).
import sys
from scapy.all import IP, UDP, Raw, send, conf
conf.verb = 0
send(IP(src=sys.argv[1], dst=sys.argv[2]) / UDP(sport=40000, dport=53) / Raw(sys.argv[3].encode()))
