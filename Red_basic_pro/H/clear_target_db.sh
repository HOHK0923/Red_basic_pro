#!/bin/bash

# 타겟 서버 DB 초기화 스크립트
# 사용법: ./clear_target_db.sh <TARGET_IP>
# 예: ./clear_target_db.sh 15.164.95.252

if [ -z "$1" ]; then
    echo "사용법: ./clear_target_db.sh <TARGET_IP>"
    echo "예: ./clear_target_db.sh 15.164.95.252"
    exit 1
fi

TARGET_IP="$1"
SSH_KEY="$HOME/.ssh/id_rsa"

echo "============================================================"
echo "🗑️  타겟 서버 데이터베이스 초기화"
echo "============================================================"
echo "타겟 IP: $TARGET_IP"

echo ""
echo "⚠️  경고: 이 작업은 타겟 서버의 게시물(posts)을 모두 삭제합니다!"
echo ""
read -p "계속하시겠습니까? (y/n): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "취소됨"
    exit 0
fi

echo ""
echo "🔌 타겟 서버에 접속 중..."

# SSH로 접속해서 PostgreSQL 명령 실행
ssh -i "$SSH_KEY" ec2-user@"$TARGET_IP" << 'EOF'
    echo ""
    echo "📊 현재 게시물 수 확인 중..."

    # PostgreSQL에서 게시물 수 확인
    POSTS_COUNT=$(sudo -u postgres psql -d vulnerable_sns -t -c "SELECT COUNT(*) FROM posts;" 2>/dev/null | tr -d ' ')

    if [ -z "$POSTS_COUNT" ]; then
        echo "❌ 데이터베이스 접속 실패"
        echo ""
        echo "다른 DB 이름일 수 있습니다. 수동으로 확인:"
        echo "  sudo -u postgres psql"
        echo "  \\l                    # DB 목록 확인"
        echo "  \\c <DB이름>           # DB 선택"
        echo "  TRUNCATE TABLE posts; # 게시물 삭제"
        exit 1
    fi

    echo "✅ 현재 게시물 수: $POSTS_COUNT"
    echo ""

    if [ "$POSTS_COUNT" -eq 0 ]; then
        echo "ℹ️  게시물이 없습니다. 초기화 불필요."
        exit 0
    fi

    echo "🗑️  게시물 삭제 중..."

    # posts 테이블 초기화
    sudo -u postgres psql -d vulnerable_sns -c "TRUNCATE TABLE posts CASCADE;" 2>/dev/null

    if [ $? -eq 0 ]; then
        echo "✅ 게시물 삭제 완료!"

        # 확인
        NEW_COUNT=$(sudo -u postgres psql -d vulnerable_sns -t -c "SELECT COUNT(*) FROM posts;" | tr -d ' ')
        echo "✅ 남은 게시물 수: $NEW_COUNT"
    else
        echo "❌ 삭제 실패"
        echo ""
        echo "수동으로 시도해보세요:"
        echo "  ssh ubuntu@$TARGET_IP"
        echo "  sudo -u postgres psql"
        echo "  \\l                          # DB 목록"
        echo "  \\c vulnerable_sns           # DB 선택 (이름 다를 수 있음)"
        echo "  SELECT * FROM posts LIMIT 5; # 게시물 확인"
        echo "  TRUNCATE TABLE posts;        # 전체 삭제"
        exit 1
    fi
EOF

if [ $? -eq 0 ]; then
    echo ""
    echo "============================================================"
    echo "✅ 타겟 서버 DB 초기화 완료!"
    echo "============================================================"
    echo ""
    echo "이제 새로운 공격 실행:"
    echo "  python3 auto.py http://$TARGET_IP http://13.158.67.78:5000"
    echo ""
else
    echo ""
    echo "============================================================"
    echo "❌ 초기화 실패"
    echo "============================================================"
    echo ""
    echo "수동으로 접속해서 확인하세요:"
    echo "  ssh -i ~/.ssh/id_rsa ec2-user@$TARGET_IP"
    echo "  sudo -u postgres psql -l    # DB 목록 확인"
    echo ""
fi
