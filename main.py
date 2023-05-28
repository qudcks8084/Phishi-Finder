# 프로젝트 메인 코드

# 필요 라이브러리 및 모듈 불러오기
from scapy.all import *
import socket
import ipaddress
import threading
import csv
from difflib import SequenceMatcher
import pandas as pd
import subprocess

# 도메인 비교 함수, 문자열 비교함수의 값을 리턴한다.
# difflib 클래스의 SequenceMatcher 함수 사용
def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()

# 사용할 CSV 파일을 읽어와 데이터프레임으로 저장
df = pd.read_csv("KR.csv", encoding="utf-8")
dm = pd.read_csv("DNSKR.csv", encoding="utf-8")

# 소켓 연결을 통해 내부 IP 확인
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect(("pwnbit.kr", 443))
MyInnerIp = socket.getsockname()[0]
print(" 내부 IP : ", MyInnerIp)

# 분석할 프로토콜 관련 정보를 담은 딕셔너리 정의
protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

# 패킷 정보 저장용 리스트 및 변수 초기화
check_list = []
dns_list = []
tcp_list = []

# DNS 패킷을 획득하는 함수 정의
# url에 대한 IP가 정의되어있는 경우, 이를 추출하기
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

# TCP 패킷을 획득하는 함수 정의
# 3way handshacking 중, 클라이언트가 서버에게 보내는 패킷 & SYN Flag가 1인 패킷을 추출한다.
# 이를 통해, 실질적인 페이지 연결이 이루어짐을 확인한다.
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

# url 도메인 비교 함수
# url내 포함된 점 갯수를 바탕으로 url을 구조화 한 후, 유사도를 구분한다.
def check_sm_kr(url):
    max = 0
    A_url = str(url)
    # url이 2개의 점으로 구분되어 있는 경우 (ex - naver.com.)
    # dm 데이터프레임의 각 도메인을 점으로 분리한 뒤, 입력된 URL의 첫 번째 부분과 비교하여 유사도(similar1)를 계산합니다. 
    # 최대 유사도인 경우 max 값을 업데이트합니다.
    if(A_url.count('.') == 2):
        for index, row in dm.iterrows():
            spurl1 = row['domain'].split('.')
            spurl2 = A_url.split('.')
            similar1 = similar(spurl1[1],spurl2[0])
            if similar1 > max :
                max = similar1
    # url이 3개의 점으로 구분되어 있는 경우 (ex - www.naver.com.)
    # dm 데이터프레임의 각 도메인과 입력된 URL 전체를 비교하여 유사도(similar0)를 계산합니다. 
    # 또한, 도메인의 첫 번째 부분과 URL의 첫 번째 부분, 두 번째 부분과 두 번째 부분 각각을 비교하여 유사도(similar1)를 계산하고, 두 유사도의 평균값(similar2)을 계산합니다.
    # 최대 유사도인 경우 max 값을 업데이트합니다.
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
    # url이 4개의 점으로 구분되어 있는 경우(www.gov.go.kr)
    # 입력된 URL을 점으로 분리한 뒤, 마지막 부분이 "kr"인 경우와 아닌 경우로 분기합니다. 
    # <"kr"인 경우 >
    # dm 데이터프레임의 각 도메인과 입력된 URL 전체를 비교하여 유사도(similar0)를 계산하고, 
    # 도메인의 첫 번째, 두 번째, 세 번째 부분과 URL의 첫 번째, 두 번째, 세 번째 부분 각각을 비교하여 유사도(similar2)를 계산합니다. 
    # 최대 유사도인 경우 max 값을 업데이트합니다. 
    # <"kr"이 아닌 경우>
    # dm 데이터프레임의 각 도메인과 URL의 첫 번째, 두 번째, 세 번째 부분 각각을 비교하여 유사도(similar0)를 계산하고, 
    # 최대 유사도인 경우 max 값을 업데이트합니다.
    elif(A_url.count('.') == 4) :
        spurl2 = A_url.split('.')
        # 도메인의 마지막 부분이 kr인 경우
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
        # kr 이 아닌경우
        else :
                for index, row in dm.iterrows():
                    check_url = row['domain']
                    spurl1 = check_url.split('.')
                    for i in range (0,3):
                        similar0 = similar(spurl1[1],spurl2[i])
                        if similar0 > max :
                            max = similar0
    
    # 비교 후 힉득한 유사도를 바탕으로 결과값 리턴
    # url 최대 유사도가 80% 이상인경우, 1을, 아니면 0을 리턴한다.
    if max > 0.8:
        return (1, max)
    else :
        return (0, max)

# 추적중인 페이지들의 IP 대역 체크 함수
def check_KR(ip) :
    ok = 0
    # 인자로 획득한 IP가 데이터프레임으로 저장한 IP 대역 내 위치하는경우 1을 리턴
    for index, row in df.iterrows():
        start_ip = ipaddress.ip_address(row['start_ip'])
        end_ip = ipaddress.ip_address(row['end_ip'])
        compare_ip = ipaddress.ip_address(ip)
        if start_ip <= compare_ip <= end_ip:
            ok = 1
    return ok

# TCP 연결을 획득 한 후, 10초간 sleep 하는 함수
# 알림의 중복 표시를 막기 위해 사용
def sleep_thread(dst_ip):
    time.sleep(10)
    tcp_list.remove(dst_ip)

# 패킷 정보 처리 함수.
# UDP 패킷인경우 dns_thread 함수를, TCP 패킷인경우 tcp_thread 함수를 생성한다.
def show_packet(packet):
    proto = packet[0][1].proto
    # UDP 패킷 처리, DNS 패킷일 가능성이 높으니 dns_thread 함수 생성
    if proto == 17:         ## dns
        threading.Thread(target=dns_thread, args=(packet,)).start()
        
    # TCP 패킷 처리
    # 패킷의 중복처리를 막고자, TCP 패킷의 목적지 IP 주소를 확인하고, 해당 IP 주소가 tcp_list에 존재하지 않는 경우에만 처리.
    # 이후 tcp_list에 목적지 IP 주소를 추가하고, tcp_thread 스레드와 sleep_thread 스레드를 생성합니다. 
    # tcp_thread 에서는 해당 IP 주소에 대한 추가적인 처리를 수행합니다.
    # sleep_thread 함수에서는 일정 시간동안 시스템을 대기시킨 후, tcp_list에서 해당 IP 주소를 제거합니다.
    elif proto == 6:        ## tcp
        dst_ip = packet[0][1].dst
        if dst_ip not in tcp_list:
            tcp_list.append(dst_ip)
            threading.Thread(target=tcp_thread, args=(packet,)).start()
            threading.Thread(target=sleep_thread, args=(dst_ip,)).start()

# 패킷 스니핑 함수
def sniffing(filter):
    sniff(filter=filter, prn=show_packet, count=0, store=0)

# 메인 코드 실행 함수
# filter 값을 통해 감지할 패킷의 종류를 설정하고, sniffing 함수로 이를 감지한다.
if __name__ == '__main__':
    filter = '((tcp port 80 or tcp port 443) and src host ' + MyInnerIp + ') or udp port 53'
    sniffing(filter)
