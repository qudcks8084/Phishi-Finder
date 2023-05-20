from scapy.all import*
import socket
import ipaddress
import threading
import csv

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect(("pwnbit.kr", 443))
MyInnerIp = socket.getsockname()[0]
print(" 내부 IP : ", MyInnerIp)

protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

wdns = open("DNS.csv",'a',newline='')

prev = None

dns_list = []
tcp_list = []

def dns_thread(packet):
    if DNSRR in packet and packet[DNS].qr == 1:
        dns_query = packet[DNSQR].qname.decode()
        # DNS 응답 레코드 추출     
        for answer in packet[DNSRR]:
            if answer.type == 1:  # IPv4 주소 타입인 경우
                ip_address = answer.rdata
                print("< DNS > [ %s | %s ] " %(ip_address, dns_query))
                dns_list.append([ip_address, 0])

def tcp_thread(packet):
    if 'S' in packet['TCP'].flags:
        dst_ip = packet[0][1].dst

        state = True

        for dns in dns_list:
            if ipaddress.ip_address(dst_ip) == ipaddress.ip_address(dns[0]) and dns[1] == 0 :
                print("< TCP > [ %s ] : is Danger ! " %dst_ip)
                state = False
                break
        
        if state == True:
            print("< TCP > [ %s ] " %dst_ip)

def sleep_thread(dst_ip):
    time.sleep(10)
    tcp_list.remove(dst_ip)

def showPacket(packet):
    proto = packet[0][1].proto

    if proto == 17:         ## dns
        threading.Thread(target=dns_thread, args=(packet)).start()
    
    elif proto == 6:        ## tcp
        dst_ip = packet[0][1].dst
        if dst_ip not in tcp_list:
            tcp_list.append(dst_ip)
            threading.Thread(target=tcp_thread, args=(packet)).start()
            threading.Thread(target=sleep_thread, args=(dst_ip, )).start()


def sniffing(filter):  
    sniff(filter = filter, prn = showPacket, count = 0, store = 0)  


def check(URL):
    read = open("DNSDanger.csv",'r',encoding="UTF-8")
    rd = csv.reader(read)
    for tem in rd:
        if tem[0] == URL :
            print(tem[0])
            print("Danger Website")
    
    return 0


if __name__ == '__main__':
    filter = '((tcp port 80 or tcp port 443) and src host ' + MyInnerIp + ') or udp port 53'
    sniffing(filter)