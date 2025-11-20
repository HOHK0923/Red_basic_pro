#!/bin/bash
###############################################################################
# 사용자 잠금 스크립트 - USER LOCKDOWN
#
# 목적: 사용자 삭제 대신 접속 차단
# - root, sysadmin만 접속 가능
# - 나머지는 계정 잠금 + Shell 무효화
#
# 사용법: sudo bash LOCKDOWN_USERS.sh
###############################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                                                           ║"
echo "║   🔒 사용자 잠금 모드 - USER LOCKDOWN 🔒                  ║"
echo "║                                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Root 권한 확인
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[-] root 권한 필요${NC}"
    echo "sudo bash $0"
    exit 1
fi

###############################################################################
# 설정
###############################################################################

# 접속 허용할 사용자 (화이트리스트)
ALLOWED_USERS=("root" "sysadmin")

echo -e "${CYAN}[*] 접속 허용 사용자: ${ALLOWED_USERS[@]}${NC}"
echo -e "${YELLOW}[*] 나머지 사용자는 모두 차단됩니다${NC}"
echo ""

read -p "계속하시겠습니까? (y/N): " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo -e "${GREEN}[+] 취소됨${NC}"
    exit 0
fi

echo ""

###############################################################################
# Phase 1: SSH 설정 - AllowUsers
###############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[Phase 1] SSH 접속 제한"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

SSHD_CONFIG="/etc/ssh/sshd_config"

if [ -f "$SSHD_CONFIG" ]; then
    # 백업
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%s)"
    echo -e "${GREEN}[+] SSH 설정 백업: ${SSHD_CONFIG}.bak${NC}"

    # AllowUsers 줄 제거 (기존 설정 있으면)
    sed -i '/^AllowUsers/d' "$SSHD_CONFIG"

    # 새로운 AllowUsers 추가
    echo "" >> "$SSHD_CONFIG"
    echo "# User Lockdown - Only these users can SSH" >> "$SSHD_CONFIG"
    echo "AllowUsers ${ALLOWED_USERS[@]}" >> "$SSHD_CONFIG"

    echo -e "${GREEN}[+] SSH 접속 허용: ${ALLOWED_USERS[@]}${NC}"

    # SSH 재시작
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    echo -e "${GREEN}[+] SSH 재시작${NC}"
else
    echo -e "${RED}[-] SSH 설정 파일 없음: $SSHD_CONFIG${NC}"
fi

echo ""

###############################################################################
# Phase 2: 계정 잠금 (passwd -l)
###############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[Phase 2] 계정 비밀번호 잠금"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 모든 일반 사용자 나열 (UID >= 1000)
ALL_USERS=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd)

LOCKED_COUNT=0

for user in $ALL_USERS; do
    # 허용 사용자는 건너뛰기
    if [[ " ${ALLOWED_USERS[@]} " =~ " ${user} " ]]; then
        echo -e "${GREEN}[SKIP] $user (허용 목록)${NC}"
        continue
    fi

    # 계정 잠금
    passwd -l "$user" &>/dev/null

    if [ $? -eq 0 ]; then
        echo -e "${YELLOW}[LOCK] $user → 비밀번호 잠금${NC}"
        ((LOCKED_COUNT++))
    else
        echo -e "${RED}[FAIL] $user → 잠금 실패${NC}"
    fi
done

echo ""
echo -e "${GREEN}[+] ${LOCKED_COUNT}명의 계정 잠금${NC}"
echo ""

###############################################################################
# Phase 3: Shell 무효화 (/sbin/nologin)
###############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[Phase 3] Shell 무효화 (로그인 차단)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

NOLOGIN_COUNT=0

for user in $ALL_USERS; do
    # 허용 사용자는 건너뛰기
    if [[ " ${ALLOWED_USERS[@]} " =~ " ${user} " ]]; then
        continue
    fi

    # 현재 Shell 확인
    CURRENT_SHELL=$(getent passwd "$user" | cut -d: -f7)

    # 이미 nologin이면 건너뛰기
    if [ "$CURRENT_SHELL" = "/sbin/nologin" ] || [ "$CURRENT_SHELL" = "/bin/false" ]; then
        echo -e "${CYAN}[SKIP] $user (이미 nologin)${NC}"
        continue
    fi

    # Shell을 /sbin/nologin으로 변경
    usermod -s /sbin/nologin "$user"

    if [ $? -eq 0 ]; then
        echo -e "${YELLOW}[NOLOGIN] $user → Shell: $CURRENT_SHELL → /sbin/nologin${NC}"
        ((NOLOGIN_COUNT++))
    else
        echo -e "${RED}[FAIL] $user → Shell 변경 실패${NC}"
    fi
done

echo ""
echo -e "${GREEN}[+] ${NOLOGIN_COUNT}명의 Shell 무효화${NC}"
echo ""

###############################################################################
# Phase 4: 활성 세션 강제 종료
###############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[Phase 4] 차단된 사용자의 활성 세션 종료"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

KILLED_COUNT=0

for user in $ALL_USERS; do
    # 허용 사용자는 건너뛰기
    if [[ " ${ALLOWED_USERS[@]} " =~ " ${user} " ]]; then
        continue
    fi

    # 사용자의 모든 프로세스 종료
    PROCESSES=$(pgrep -u "$user" 2>/dev/null | wc -l)

    if [ "$PROCESSES" -gt 0 ]; then
        pkill -9 -u "$user" 2>/dev/null
        echo -e "${YELLOW}[KILL] $user → ${PROCESSES}개 프로세스 종료${NC}"
        ((KILLED_COUNT++))
    fi
done

echo ""
if [ $KILLED_COUNT -gt 0 ]; then
    echo -e "${GREEN}[+] ${KILLED_COUNT}명의 세션 종료${NC}"
else
    echo -e "${CYAN}[*] 종료할 세션 없음${NC}"
fi
echo ""

###############################################################################
# 최종 보고서
###############################################################################
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                                                           ║"
echo "║   ✅ 사용자 잠금 완료 - USER LOCKDOWN COMPLETE ✅          ║"
echo "║                                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}최종 보고서${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${GREEN}[✓] SSH 접속 허용: ${ALLOWED_USERS[@]}${NC}"
echo -e "${GREEN}[✓] 계정 잠금: ${LOCKED_COUNT}명${NC}"
echo -e "${GREEN}[✓] Shell 무효화: ${NOLOGIN_COUNT}명${NC}"
echo -e "${GREEN}[✓] 세션 종료: ${KILLED_COUNT}명${NC}"
echo ""

echo -e "${YELLOW}[*] 차단된 사용자 목록:${NC}"
for user in $ALL_USERS; do
    if [[ ! " ${ALLOWED_USERS[@]} " =~ " ${user} " ]]; then
        echo "    - $user"
    fi
done
echo ""

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}차단 효과${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "1. SSH 접속 시도:"
echo "   → Permission denied (AllowUsers에 없음)"
echo ""
echo "2. 비밀번호 입력:"
echo "   → Authentication failed (계정 잠김)"
echo ""
echo "3. 로그인 성공해도:"
echo "   → This account is currently not available (Shell이 /sbin/nologin)"
echo ""

echo -e "${GREEN}[+] root와 sysadmin만 접속 가능!${NC}"
echo ""

###############################################################################
# 복구 방법 안내
###############################################################################
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}복구 방법 (나중에 필요하면)${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "# 특정 사용자 복구"
echo "passwd -u ec2-user              # 계정 잠금 해제"
echo "usermod -s /bin/bash ec2-user   # Shell 복구"
echo ""
echo "# SSH 설정 복구"
echo "vi /etc/ssh/sshd_config         # AllowUsers 줄 삭제"
echo "systemctl restart sshd          # SSH 재시작"
echo ""
