# 복구 스크립트 사용법

## 🎯 상황별 사용 가이드

### 상황 1: 지금 서버 접속이 안됨 (ERR_CONNECTION_TIMED_OUT)
→ **SIMPLE_RESTORE.sh** 사용

```bash
# 서버 접속 (백도어 사용자)
ssh sysadmin@3.35.22.248
# 비밀번호: Adm1n!2024#Secure

# 복구 실행
sudo bash /tmp/SIMPLE_RESTORE.sh
```

**효과**:
- ✅ .htaccess 제거 (다른 페이지들 접근 가능)
- ✅ index.php 간단한 메인 페이지로 복구
- ✅ login.php, upload.php 등 기존 페이지 유지
- ✅ 백도어 유지됨

---

### 상황 2: 데모를 보여주고 싶을 때

**1단계: 정상 사이트 보여주기**
```bash
sudo bash /tmp/SIMPLE_RESTORE.sh
```
→ 일반적인 웹사이트처럼 보임

**2단계: 해킹된 사이트 보여주기**
```bash
sudo bash /tmp/SHOW_HACKED.sh
```
→ Matrix 애니메이션 + "SYSTEM COMPROMISED" 페이지

**3단계: 다시 정상으로**
```bash
sudo bash /tmp/SIMPLE_RESTORE.sh
```

---

## 📁 스크립트 파일 설명

### SIMPLE_RESTORE.sh (권장!)
- **목적**: 웹사이트만 정상으로 복구
- **유지**: 백도어, login.php, upload.php
- **제거**: .htaccess (리다이렉트), 해킹 페이지

### SHOW_HACKED.sh
- **목적**: 해킹 페이지로 전환
- **추가**: Matrix 애니메이션, 공격 체인 설명
- **유지**: 백도어

### DEMO_RESTORE.sh
- **목적**: 데모용 정상 페이지 (더 예쁨)
- **차이**: SIMPLE_RESTORE보다 디자인이 좋음

### EMERGENCY_RECOVERY.sh
- **목적**: 완전 복구 (백도어도 제거)
- **주의**: 백도어까지 모두 제거됨!

---

## 🚀 빠른 실행 (추천)

```bash
# 1. 서버 접속
ssh sysadmin@3.35.22.248
# 비밀번호: Adm1n!2024#Secure

# 2. 스크립트 생성 및 실행 (한 번에)
cat > /tmp/fix.sh << 'EOFFIX'
#!/bin/bash
echo "웹사이트 복구 중..."
sudo find /var/www/html/www -name ".htaccess" -delete
sudo systemctl restart httpd
echo "✅ 완료! 이제 사이트 접속 가능합니다."
EOFFIX

bash /tmp/fix.sh
```

---

## 🔍 문제 해결

### 문제: 여전히 접속 안됨
```bash
# Apache 상태 확인
sudo systemctl status httpd

# 에러 로그 확인
sudo tail -100 /var/log/httpd/error_log

# Apache 재시작
sudo systemctl restart httpd
```

### 문제: login.php, upload.php가 없어짐
```bash
# 백업 파일 확인
ls -la /var/www/html/www/*.backup

# 백업에서 복구
sudo cp /var/www/html/www/login.php.backup /var/www/html/www/login.php
sudo cp /var/www/html/www/upload.php.backup /var/www/html/www/upload.php
```

### 문제: 백도어가 사라짐
```bash
# Cron이 5분마다 자동 복구함
# 5분 기다리거나 수동 실행:
sudo bash /usr/local/bin/backdoor_keeper.sh
```

---

## 📝 스크립트 전송 명령어

```bash
# 로컬에서 실행 (Mac/Linux)
scp /Users/hwangjunha/Desktop/Red_basic_local/H/2025-11-14/PORTFOLIO_AWS_IMDS_ATTACK/recovery/SIMPLE_RESTORE.sh sysadmin@3.35.22.248:/tmp/

scp /Users/hwangjunha/Desktop/Red_basic_local/H/2025-11-14/PORTFOLIO_AWS_IMDS_ATTACK/recovery/SHOW_HACKED.sh sysadmin@3.35.22.248:/tmp/
```

---

## ✅ 현재 상황 해결 (즉시!)

서버 접속이 안되는 상황이면:

```bash
# 서버에 SSH 접속
ssh sysadmin@3.35.22.248

# 즉시 실행할 명령어들
sudo find /var/www/html/www -name ".htaccess" -delete
sudo systemctl restart httpd

# 확인
curl http://localhost/
```

이제 접속되어야 합니다!
