#!/bin/bash
###############################################################################
# 빠른 원본 사이트 복구
# 서버에 있는 원본 파일들을 찾아서 복구
###############################################################################

echo "╔═══════════════════════════════════════════════╗"
echo "║   원본 사이트 빠른 복구                      ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# 1. .htaccess 제거 (가장 중요!)
echo "[1/3] .htaccess 제거 중..."
sudo find /var/www/html/www -name ".htaccess" -delete 2>/dev/null
echo "  ✅ .htaccess 제거 완료"
echo ""

# 2. 원본 파일 찾기
echo "[2/3] 원본 파일 찾는 중..."

# 가능한 경로들
PATHS=(
    "/home/ec2-user/vulnerable-sns"
    "/home/ec2-user/Red_basic_local/H/2025-11-14/vulnerable-sns"
    "/opt/vulnerable-sns"
    "/tmp/vulnerable-sns"
    "/var/www/vulnerable-sns"
)

FOUND=0
for path in "${PATHS[@]}"; do
    if [ -d "$path" ]; then
        echo "  ✅ 원본 발견: $path"

        # 파일 복사
        echo ""
        echo "[3/3] 파일 복구 중..."
        sudo cp "$path"/*.php /var/www/html/www/ 2>/dev/null && echo "  - PHP 파일들 복구됨"

        # 권한 설정
        sudo chown -R apache:apache /var/www/html/www
        sudo find /var/www/html/www -type f -exec chmod 644 {} \;

        # Apache 재시작
        sudo systemctl restart httpd

        FOUND=1
        break
    fi
done

if [ $FOUND -eq 0 ]; then
    echo "  ⚠️  원본 폴더를 찾을 수 없습니다"
    echo ""
    echo "  다음 명령어로 직접 찾아보세요:"
    echo "  find /home -name \"vulnerable-sns\" -type d 2>/dev/null"
    echo "  find /opt -name \"vulnerable-sns\" -type d 2>/dev/null"
fi

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║   ✅ 복구 완료!                              ║"
echo "║                                              ║"
echo "║   사이트: http://3.35.22.248/                ║"
echo "╚═══════════════════════════════════════════════╝"
