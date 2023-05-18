#!/usr/bin/python  
from scapy.all import*  
import socket
import dns.resolver, dns.reversename
import requests
import re

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect(("pwnbit.kr",443))
MyInnerIp = socket.getsockname()[0]
print(" 내부 IP : ", MyInnerIp)
  
protocols = {1:'ICMP', 6:'TCP', 17:'UDP'}  
  
def showPacket(packet):  
    src_ip = packet[0][1].src  
    dst_ip = packet[0][1].dst 
    proto = packet[0][1].proto  
  
    if proto in protocols:
        if(proto == 6 and src_ip == MyInnerIp):
            print ("[ %s ] %s -> %s" %(protocols[proto], src_ip, dst_ip))
            
        if proto == 1:  
            print ("TYPE: [%d], CODE[%d]" %(packet[0][2].type, packet[0][2].code))
  
def sniffing(filter):  
    sniff(filter = filter, prn = showPacket, count = 0)  
  
if __name__ == '__main__':  
    filter = 'tcp port 80 or udp port 80 or tcp port 443 or udp port 443'  
    sniffing(filter)