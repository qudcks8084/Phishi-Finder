from scapy.all import *
import subprocess
import csv


wdns = open("DNS.csv",'a',newline='')

def send_system_notification(title, message):
    command = f'display notification "{message}" with title "{title}"'
    subprocess.call(['osascript', '-e', command])

def process_dns_packet(packet):
    if DNSRR in packet and packet[DNS].qr == 1:  # DNS QR 필드가 1이면 DNS 응답 패킷
        src_ip = packet[IP].src
        dns_query = packet[DNSQR].qname.decode()

        # DNS 응답 레코드 추출     
        for answer in packet[DNSRR]:
            if answer.type == 1:  # IPv4 주소 타입인 경우
                ip_address = answer.rdata
                print(f"DNS Response to {src_ip} - Domain: {dns_query}, IP: {ip_address}")
                cheak(dns_query)
                    
                wdns.write(f"{dns_query},{ip_address}\n")
                wdns.flush()  # 버퍼를 비워서 즉시 파일에 쓰도록 함

def cheak(URL):
    read = open("DNSDanger.csv",'r',encoding="UTF-8")
    rd = csv.reader(read)
    for tem in rd:
            if tem[0] == URL :
                print(tem[0])
                print("Danger Website")
    
    
# 패킷 캡처 및 분석
sniff(filter="udp port 53", prn=process_dns_packet, count=0)
