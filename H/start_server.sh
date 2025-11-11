#!/bin/bash
# CSRF 공격자 서버 시작 스크립트

echo "============================================================"
echo "🎯 CSRF Attack Server - 시작 스크립트"
echo "============================================================"
echo ""

# Flask 설치 확인
if ! python3 -c "import flask" 2>/dev/null; then
    echo "[*] Flask 설치 중..."
    pip3 install flask
    echo ""
fi

# 기존 프로세스 종료
echo "[*] 기존 프로세스 확인 중..."
pkill -f attacker_server.py 2>/dev/null
sleep 1

# 서버 시작
echo "[*] 서버 시작 중..."
nohup python3 attacker_server.py > server.log 2>&1 &
SERVER_PID=$!

sleep 2

# 프로세스 확인
if ps -p $SERVER_PID > /dev/null; then
    echo ""
    echo "✅ 서버가 백그라운드에서 실행 중입니다!"
    echo ""
    echo "📊 Dashboard: http://0.0.0.0:5000/"
    echo "🎁 Fake Gift: http://0.0.0.0:5000/fake-gift"
    echo "📋 Logs:      tail -f server.log"
    echo "🛑 종료:      pkill -f attacker_server.py"
    echo ""
    echo "PID: $SERVER_PID"
    echo ""
else
    echo "❌ 서버 시작 실패. 로그를 확인하세요:"
    echo "cat server.log"
fi

echo "============================================================"
