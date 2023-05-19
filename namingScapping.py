#!/usr/bin/python
from scapy.all import*
import socket
import ipaddress
import pandas as pd

df = pd.read_csv("asn4.csv", encoding="utf-8")

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect(("pwnbit.kr", 443))
MyInnerIp = socket.getsockname()[0]
print(" 내부 IP : ", MyInnerIp)

protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

prev = None

def showPacket(packet):
    global prev
    src_ip = packet[0][1].src
    dst_ip = packet[0][1].dst
    proto = packet[0][1].proto
    
    """if src_ip != prev:
        if proto in protocols:
            if proto == 6 and dst_ip == MyInnerIp:
                CompanyCode, CompanyName, domain = findname(src_ip)
                print("< %s > [ %s | %s | %s | %s ] " %(protocols[proto], src_ip, domain ,CompanyCode, CompanyName))
                prev = src_ip

            if proto == 1:
                print("TYPE: [%d], CODE[%d]" % (packet[0][2].type, packet[0][2].code))
                prev = src_ip
                """
                
    if DNSRR in packet and packet[DNS].qr == 1:  # DNS QR 필드가 1이면 DNS 응답 패킷
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dns_query = packet[DNSQR].qname.decode()
        # DNS 응답 레코드 추출     
        for answer in packet[DNSRR]:
            if answer.type == 1:  # IPv4 주소 타입인 경우
                ip_address = answer.rdata
                CompanyCode, Companyname , domain= findname(ip_address)
                print("< DNS > [ %s | %s : %s | %s | %s ] " %(ip_address, dns_query, domain, CompanyCode, Companyname))

def findname(src_ip):
    CompanyCode = 'Unknown'
    CompanyName = 'Unknown'
    Domain = 'Unknown'
    for index, row in df.iterrows():
        start_ip = ipaddress.ip_address(row['start_ip'])
        end_ip = ipaddress.ip_address(row['end_ip'])
        compare_ip = ipaddress.ip_address(src_ip)
        if start_ip <= compare_ip <= end_ip:
            CompanyCode = row['asn']
            CompanyName = row['name']
            Domain = row['domain']
            break
    return CompanyCode, CompanyName, Domain

def sniffing(filter):  
    sniff(filter = filter, prn = showPacket, count = 0, store = 0)  

if __name__ == '__main__':
    filter = 'tcp port 80 or tcp port 443 or udp port 53'
    sniffing(filter)
