#!/bin/bash
cd /Users/hwangjunha/Desktop/Red_basic_local/H/reports
echo "============================================================"
echo "🎁 fake-gift.html 서버 시작"
echo "============================================================"
echo ""
echo "접속 URL: http://localhost:8000/fake-gift.html"
echo ""
echo "테스트 순서:"
echo "1. http://52.78.221.104/login.php에서 admin 로그인"
echo "2. http://localhost:8000/fake-gift.html 접속"
echo "3. http://13.158.67.78:5000/ 대시보드 확인"
echo ""
echo "============================================================"
echo ""
python3 -m http.server 8000
