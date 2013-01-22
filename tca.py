#!/usr/bin/python

import sys
import requests

from scapy.all import *

# TCP Connection to the directory authorities

def tcp_connection_check(directory_authorities):
    for directory in directory_authorities:
        host_addr, host_port = directory.split(":")
        host_port = int(host_port)
        ans, unans = sr(IP(dst=host_addr)/TCP(dport=int(host_port),flags="S"), verbose=0)
        ans.summary(lfilter = lambda (s,r): r.sprintf("%TCP.flags%") == "SA",
        prn=lambda(s,r):r.sprintf("TCP connection successful to %IP.src%:%TCP.sport% "))

# Download consensus from directory authorities

def dl_consensus(directory_authorities):
    for directory in directory_authorities:
        r = requests.get("http://" + directory + "/tor/status-vote/current/consensus.z")
        if r.status_code == requests.codes.ok:
            with open("consensus_"+directory+".z", "wb") as file:
                file.write(r.content)
            print "[*] OK Consensus downloaded"
            
# Connect to Tor public relay

def tor_connection():
    pass

    
directory_authorities = [ '128.31.0.39:9131', '86.59.21.38:80',
                          '194.109.206.212:80', '76.73.17.194:9030',
                          '212.112.245.170:80', '193.23.244.244:80',
                          '208.83.223.34:443', '171.25.193.9:443',
                          '154.35.32.5:80' ]
                          
bridges_torproject_org = ['bridges.torproject.org:443']

tcp_connection_check(directory_authorities)

tcp_connection_check(bridges_torproject_org)

#dl_consensus(directory_authorities)
