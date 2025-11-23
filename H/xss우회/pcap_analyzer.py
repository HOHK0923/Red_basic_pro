#!/usr/bin/env python3
"""
PCAP Analyzer - Wireshark 캡처 파일에서 쿠키 추출
기존에 캡처한 .pcap 파일 분석
"""

import sys
import re
from collections import defaultdict

try:
    from scapy.all import *
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("Error: scapy가 설치되지 않았습니다.")
    print("설치: pip3 install scapy")
    sys.exit(1)

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    END = '\033[0m'
    BOLD = '\033[1m'

def analyze_pcap(pcap_file, target_domain=None):
    """PCAP 파일 분석"""

    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}📂 PCAP Analyzer - Cookie Extractor{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}\n")

    print(f"{Colors.BLUE}File: {pcap_file}{Colors.END}\n")

    try:
        packets = rdpcap(pcap_file)
        print(f"{Colors.GREEN}✓ {len(packets)} 패킷 로드 완료{Colors.END}\n")
    except Exception as e:
        print(f"{Colors.RED}✗ 파일 읽기 실패: {e}{Colors.END}")
        return

    cookies = []
    credentials = []
    sessions = defaultdict(list)

    print(f"{Colors.BOLD}분석 중...{Colors.END}\n")

    for packet in packets:
        # HTTP Request
        if packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]

            host = http.Host.decode() if http.Host else ""

            # 도메인 필터
            if target_domain and target_domain not in host:
                continue

            # Cookie 추출
            if http.Cookie:
                cookie = http.Cookie.decode()

                print(f"{Colors.CYAN}[HTTP Request]{Colors.END}")
                print(f"  Host: {host}")
                print(f"  Path: {http.Path.decode()}")
                print(f"{Colors.GREEN}  Cookie: {cookie}{Colors.END}\n")

                # PHPSESSID 추출
                session_match = re.search(r'PHPSESSID=([a-zA-Z0-9]+)', cookie)
                if session_match:
                    session_id = session_match.group(1)
                    src_ip = packet[IP].src if packet.haslayer(IP) else 'Unknown'

                    sessions[session_id].append({
                        'host': host,
                        'path': http.Path.decode(),
                        'src_ip': src_ip,
                        'cookie': cookie
                    })

                cookies.append({
                    'host': host,
                    'path': http.Path.decode(),
                    'cookie': cookie
                })

            # POST 데이터 (로그인 credential)
            if http.Method == b'POST' and packet.haslayer(Raw):
                try:
                    load = packet[Raw].load.decode()

                    username_match = re.search(r'username=([^&]+)', load)
                    password_match = re.search(r'password=([^&]+)', load)

                    if username_match and password_match:
                        print(f"{Colors.RED}[Credentials Captured!]{Colors.END}")
                        print(f"  Host: {host}")
                        print(f"  Username: {username_match.group(1)}")
                        print(f"  Password: {password_match.group(1)}\n")

                        credentials.append({
                            'host': host,
                            'username': username_match.group(1),
                            'password': password_match.group(1)
                        })
                except:
                    pass

        # HTTP Response - Set-Cookie
        elif packet.haslayer(HTTPResponse):
            http = packet[HTTPResponse]

            if http.Set_Cookie:
                set_cookie = http.Set_Cookie.decode()

                print(f"{Colors.PURPLE}[HTTP Response - Set-Cookie]{Colors.END}")
                print(f"  {set_cookie}\n")

                session_match = re.search(r'PHPSESSID=([a-zA-Z0-9]+)', set_cookie)
                if session_match:
                    session_id = session_match.group(1)
                    print(f"{Colors.GREEN}  ✓ New Session: {session_id}{Colors.END}\n")

    # 결과 요약
    print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}📊 분석 결과{Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")

    print(f"총 쿠키: {len(cookies)}개")
    print(f"고유 세션: {len(sessions)}개")
    print(f"Credentials: {len(credentials)}개\n")

    # 세션 정보 출력
    if sessions:
        print(f"{Colors.BOLD}캡처된 세션 ID:{Colors.END}\n")
        for session_id, requests in sessions.items():
            print(f"{Colors.CYAN}PHPSESSID: {session_id}{Colors.END}")
            print(f"  사용 횟수: {len(requests)}회")
            print(f"  Source IP: {requests[0]['src_ip']}")
            print(f"  예시 요청: {requests[0]['host']}{requests[0]['path']}")
            print()

    # Credentials 출력
    if credentials:
        print(f"{Colors.BOLD}캡처된 Credentials:{Colors.END}\n")
        for cred in credentials:
            print(f"{Colors.RED}Host: {cred['host']}{Colors.END}")
            print(f"{Colors.RED}  Username: {cred['username']}{Colors.END}")
            print(f"{Colors.RED}  Password: {cred['password']}{Colors.END}")
            print()

    # 파일로 저장
    if sessions:
        with open('extracted_sessions.txt', 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("Extracted Sessions from PCAP\n")
            f.write("=" * 80 + "\n\n")

            for session_id, requests in sessions.items():
                f.write(f"PHPSESSID: {session_id}\n")
                f.write(f"Source IP: {requests[0]['src_ip']}\n")
                f.write(f"Requests: {len(requests)}\n")
                f.write(f"Example: {requests[0]['host']}{requests[0]['path']}\n")
                f.write(f"Full Cookie: {requests[0]['cookie']}\n")
                f.write("\n" + "-" * 80 + "\n\n")

        print(f"{Colors.GREEN}✓ 세션 저장: extracted_sessions.txt{Colors.END}\n")

    if credentials:
        with open('extracted_credentials.txt', 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("Extracted Credentials from PCAP\n")
            f.write("=" * 80 + "\n\n")

            for cred in credentials:
                f.write(f"Host: {cred['host']}\n")
                f.write(f"Username: {cred['username']}\n")
                f.write(f"Password: {cred['password']}\n")
                f.write("\n" + "-" * 80 + "\n\n")

        print(f"{Colors.GREEN}✓ Credentials 저장: extracted_credentials.txt{Colors.END}\n")

def main():
    import argparse

    parser = argparse.ArgumentParser(description='PCAP Cookie Analyzer')
    parser.add_argument('pcap_file', help='PCAP 파일 경로')
    parser.add_argument('-d', '--domain', help='필터링할 도메인 (선택)')
    args = parser.parse_args()

    if not os.path.exists(args.pcap_file):
        print(f"{Colors.RED}Error: 파일을 찾을 수 없습니다: {args.pcap_file}{Colors.END}")
        sys.exit(1)

    analyze_pcap(args.pcap_file, args.domain)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠ 중단됨{Colors.END}")
        sys.exit(0)
