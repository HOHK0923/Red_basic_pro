#!/bin/bash
# CSRF 공격자 서버 종료 스크립트

echo "============================================================"
echo "🛑 CSRF Attack Server - 종료 스크립트"
echo "============================================================"
echo ""

# 실행 중인 프로세스 확인
if pgrep -f attacker_server.py > /dev/null; then
    echo "[*] 실행 중인 서버 발견"

    # 프로세스 정보 표시
    ps aux | grep attacker_server.py | grep -v grep

    echo ""
    echo "[*] 서버 종료 중..."
    pkill -f attacker_server.py

    sleep 1

    # 종료 확인
    if ! pgrep -f attacker_server.py > /dev/null; then
        echo "✅ 서버가 정상적으로 종료되었습니다."
    else
        echo "⚠️  정상 종료 실패, 강제 종료 중..."
        pkill -9 -f attacker_server.py
        sleep 1
        echo "✅ 강제 종료 완료"
    fi
else
    echo "ℹ️  실행 중인 서버가 없습니다."
fi

echo ""
echo "============================================================"
