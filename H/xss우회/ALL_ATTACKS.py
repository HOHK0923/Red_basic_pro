#!/usr/bin/env python3
"""
All-In-One Attack Scanner
XSS/SQLi 막혔을 때 쓰는 모든 공격 기법
"""

import subprocess
import sys

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    END = '\033[0m'
    BOLD = '\033[1m'

def main():
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}🔥 All-In-One Attack Scanner{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.END}\n")

    print(f"{Colors.BLUE}Target: http://healthmash.net (54.180.32.176){Colors.END}\n")

    print(f"{Colors.YELLOW}XSS와 SQLi가 막혔을 때 사용하는 대안 공격들:{Colors.END}\n")

    scanners = [
        ("🎣 CSRF (계정 탈취)", "csrf_exploit.py"),
        ("📂 LFI/Path Traversal (세션 파일 읽기)", "lfi_scanner.py"),
        ("🎯 IDOR (직접 객체 참조)", "idor_scanner.py"),
        ("↪️  Open Redirect (리다이렉트 악용)", "redirect_scanner.py"),
    ]

    print(f"{Colors.BOLD}실행할 스캐너:{Colors.END}\n")
    for idx, (name, script) in enumerate(scanners, 1):
        print(f"  {idx}. {name}")

    print(f"\n{Colors.BOLD}{'='*80}{Colors.END}\n")

    # 모든 스캐너 실행
    for idx, (name, script) in enumerate(scanners, 1):
        print(f"\n{Colors.BOLD}{Colors.PURPLE}[{idx}/{len(scanners)}] {name}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.PURPLE}{'='*80}{Colors.END}\n")

        try:
            result = subprocess.run(
                ['python3', script],
                capture_output=True,
                text=True,
                timeout=60
            )

            print(result.stdout)

            if result.returncode != 0 and result.stderr:
                print(f"{Colors.RED}오류:{Colors.END}")
                print(result.stderr)

        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}✗ 타임아웃 (60초 초과){Colors.END}\n")
        except FileNotFoundError:
            print(f"{Colors.RED}✗ 파일 없음: {script}{Colors.END}\n")
        except Exception as e:
            print(f"{Colors.RED}✗ 오류: {e}{Colors.END}\n")

        print(f"\n{Colors.BOLD}{'='*80}{Colors.END}\n")
        input(f"{Colors.YELLOW}다음 스캐너 실행하려면 Enter...{Colors.END} ")

    print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}✓ 모든 스캔 완료!{Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.END}\n")

    print(f"{Colors.YELLOW}결과 요약:{Colors.END}")
    print(f"  - 취약점이 발견되면 위 출력에서 ✓ 표시 확인")
    print(f"  - CSRF가 성공하면 csrf_attack.html 파일 생성됨")
    print(f"  - 각 스캐너의 출력을 확인하여 성공한 공격 확인\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}⚠ 중단됨{Colors.END}")
        sys.exit(0)
