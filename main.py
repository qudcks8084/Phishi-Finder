# 프로젝트 메인 코드

from scapy.all import *
import socket
import ipaddress
import threading
import csv
from difflib import SequenceMatcher
import pandas as pd
import subprocess

# 도메인 비교 함수, 문자열 비교함수의 값을 리턴한다.
def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()

df = pd.read_csv("KR.csv", encoding="utf-8")
dm = pd.read_csv("DNSKR.csv", encoding="utf-8")

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect(("pwnbit.kr", 443))
MyInnerIp = socket.getsockname()[0]
print(" 내부 IP : ", MyInnerIp)

protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

check_list = []
dns_list = []
tcp_list = []

def dns_thread(packet):
    if DNSRR in packet and packet[DNS].qr == 1:
        dns_query = packet[DNSQR].qname.decode()
        url = dns_query.replace(",", "")
        # DNS 응답 레코드 추출
        for answer in packet[DNSRR]:
            if answer.type == 1:  # IPv4 주소 타입인 경우
                ip_address = answer.rdata
                a, b = check_sm_kr(url)
                print("< DNS > [ %s | %s ] check : %s - %s" %(ip_address, dns_query,a,b))

                if ip_address not in dns_list:
                    dns_list.append([ip_address, a])

def tcp_thread(packet):
    if 'S' in packet['TCP'].flags:
        dst_ip = packet[0][1].dst
        ok = check_KR(dst_ip)
        # 정부페이지 IP대역에 속한 IP일경우, KR.py를 통해 알림
        if ok == 1 :
            print("< TCP > [ %s ] : KOREA NATIONAL OFFICIAL WEBSITE ! " %dst_ip)
            subprocess.run(["python", "KR.py"])
        # 아닌경우
        else :
            for dns in dns_list:
                if ipaddress.ip_address(dst_ip) == ipaddress.ip_address(dns[0]):
                    # dns 테이블과 대조, 해당 IP가 피싱 의심페이지일경우 알림
                    if dns[1] == 1:
                        print("< TCP > [ %s ] : THIS WEBSITE CAN BE PHISHING SITE! " %dst_ip)
                        subprocess.run(["python", "Danger.py"])
                    else :
                        print("< TCP > [ %s ] " %dst_ip)

def check_sm_kr(url):
    max = 0
    A_url = str(url)
    if(A_url.count('.') == 2):
        for index, row in dm.iterrows():
            spurl1 = row['domain'].split('.')
            spurl2 = A_url.split('.')
            similar1 = similar(spurl1[1],spurl2[0])
            if similar1 > max :
                max = similar1
    elif(A_url.count('.') == 3) :
        for index, row in dm.iterrows():
            check_url = row['domain']
            spurl1 = check_url.split('.')
            spurl2 = A_url.split('.')
            similar0 = similar(check_url,A_url)
            if similar0 > max :
                max = similar0
            similar1 = similar(spurl1[1],spurl2[1])
            if similar1 > max :
                max = similar1
            similar2 = (similar(spurl1[1],spurl2[1]) + similar(spurl1[0],spurl2[0]))/2
            if similar2 > max :
                max = similar2
    elif(A_url.count('.') == 4) :
        spurl2 = A_url.split('.')
        if spurl2[3] == "kr" :
                for index, row in dm.iterrows():
                    check_url = row['domain']
                    spurl1 = check_url.split('.')
                    similar0 = similar(check_url,A_url)
                    if similar0 > max :
                        max = similar0
                    similar2 = (similar(spurl1[0],spurl2[0]) + similar(spurl1[1],spurl2[1])+ similar(spurl1[2],spurl2[2]))/3
                    if similar2 > max :
                        max = similar2
        else :
                for index, row in dm.iterrows():
                    check_url = row['domain']
                    spurl1 = check_url.split('.')
                    for i in range (0,3):
                        similar0 = similar(spurl1[1],spurl2[i])
                        if similar0 > max :
                            max = similar0

    
    if max > 0.8:
        return (1, max)
    else :
        return (0, max)


def check_KR(ip) :
    ok = 0
    for index, row in df.iterrows():
        start_ip = ipaddress.ip_address(row['start_ip'])
        end_ip = ipaddress.ip_address(row['end_ip'])
        compare_ip = ipaddress.ip_address(ip)
        if start_ip <= compare_ip <= end_ip:
            ok = 1
    return ok

def sleep_thread(dst_ip):
    time.sleep(10)
    tcp_list.remove(dst_ip)

def show_packet(packet):
    proto = packet[0][1].proto

    if proto == 17:         ## dns
        threading.Thread(target=dns_thread, args=(packet,)).start()

    elif proto == 6:        ## tcp
        dst_ip = packet[0][1].dst
        if dst_ip not in tcp_list:
            tcp_list.append(dst_ip)
            threading.Thread(target=tcp_thread, args=(packet,)).start()
            threading.Thread(target=sleep_thread, args=(dst_ip,)).start()


def sniffing(filter):
    sniff(filter=filter, prn=show_packet, count=0, store=0)


if __name__ == '__main__':
    filter = '((tcp port 80 or tcp port 443) and src host ' + MyInnerIp + ') or udp port 53'
    sniffing(filter)
