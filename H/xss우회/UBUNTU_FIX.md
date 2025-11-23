# Ubuntu Flask 설치 오류 해결

## 🚨 문제
```
pip3 install flask
error: externally-managed-environment
```

이것은 최신 Ubuntu/Debian 시스템의 보호 기능입니다.

---

## ✅ 해결 방법 (3가지)

### 방법 1: --break-system-packages 사용 (가장 빠름) ⭐⭐⭐⭐⭐

```bash
# Flask 설치 (시스템 패키지 보호 무시)
pip3 install flask --break-system-packages

# 또는 전체 명령어
pip3 install flask --break-system-packages && \
chmod +x *.py *.sh && \
nohup python3 cookie_listener.py > listener.log 2>&1 & \
sleep 2 && tail -f listener.log
```

**장점**: 빠르고 간단
**단점**: 시스템 Python 패키지에 영향 가능 (하지만 실습 환경에서는 괜찮음)

---

### 방법 2: apt로 시스템 패키지 설치 (안전) ⭐⭐⭐⭐

```bash
# Flask를 시스템 패키지로 설치
sudo apt update
sudo apt install python3-flask -y

# 리스너 실행
chmod +x *.py *.sh
nohup python3 cookie_listener.py > listener.log 2>&1 &
sleep 2 && tail -f listener.log
```

**장점**: 안전하고 권장되는 방법
**단점**: sudo 권한 필요

---

### 방법 3: 가상환경 사용 (가장 안전) ⭐⭐⭐

```bash
# 가상환경 생성
python3 -m venv ~/venv

# 가상환경 활성화
source ~/venv/bin/activate

# Flask 설치
pip3 install flask

# 리스너 실행
chmod +x *.py *.sh
nohup python3 cookie_listener.py > listener.log 2>&1 &
sleep 2 && tail -f listener.log

# 나중에 비활성화하려면
# deactivate
```

**장점**: 가장 안전하고 깔끔
**단점**: 매번 가상환경 활성화 필요

---

## 🚀 추천 방법 (빠른 실행)

**실습/테스트 환경이므로 방법 1을 추천합니다:**

```bash
# 서버에서 실행 (한 줄 복사)
pip3 install flask --break-system-packages && \
chmod +x cookie_listener.py && \
nohup python3 cookie_listener.py > listener.log 2>&1 & \
sleep 2 && tail -f listener.log
```

---

## 🧪 설치 확인

```bash
# Flask가 설치되었는지 확인
python3 -c "import flask; print(flask.__version__)"

# 예상 출력: 3.0.0 (또는 버전 번호)
```

---

## 📊 전체 프로세스 (업데이트)

### 로컬에서:
```bash
# 1. 파일 전송
chmod 400 "$HOME/Downloads/A team.pem"
cd ~/Desktop/Red_basic_local/H/xss우회
scp -i "$HOME/Downloads/A team.pem" \
    cookie_listener.py \
    deploy_listener.sh \
    ubuntu@3.113.201.239:~/

# 2. SSH 접속
ssh -i "$HOME/Downloads/A team.pem" ubuntu@3.113.201.239
```

### 서버(3.113.201.239)에서:
```bash
# 3. Flask 설치 (--break-system-packages 사용)
pip3 install flask --break-system-packages

# 4. 실행 권한 부여
chmod +x cookie_listener.py deploy_listener.sh

# 5. 방화벽 설정 (필요시)
sudo ufw allow 8888/tcp
sudo ufw status

# 6. 리스너 시작 (백그라운드)
nohup python3 cookie_listener.py > listener.log 2>&1 &

# 7. 로그 확인
tail -f listener.log

# 출력 예시:
# 🎯 Cookie Listener Server Started
# 📡 Listening on: http://0.0.0.0:8888
# 🔗 Webhook URL: http://3.113.201.239:8888/steal
```

---

## 🔍 문제 해결

### 여전히 오류 발생 시

```bash
# Python 버전 확인
python3 --version

# pip 버전 확인
pip3 --version

# pip 업그레이드
python3 -m pip install --upgrade pip --break-system-packages

# Flask 재설치
pip3 install flask --break-system-packages
```

### 포트 8888이 이미 사용 중인 경우

```bash
# 포트 사용 확인
sudo lsof -i :8888

# 프로세스 종료
kill $(sudo lsof -t -i:8888)

# 리스너 재시작
python3 cookie_listener.py
```

---

## 🎯 빠른 시작 (원라인 - 복사해서 붙여넣기)

```bash
pip3 install flask --break-system-packages && chmod +x cookie_listener.py && nohup python3 cookie_listener.py > listener.log 2>&1 & sleep 2 && tail -f listener.log
```

이제 리스너가 실행되고 있습니다! 🚀

---

## 📡 동작 확인 (로컬에서)

```bash
# 헬스체크
curl http://3.113.201.239:8888/health

# 예상 응답:
# {"status":"ok","message":"Cookie listener is running"}
```

---

**준비 완료! XSS 공격을 시작하세요!** 🎯
