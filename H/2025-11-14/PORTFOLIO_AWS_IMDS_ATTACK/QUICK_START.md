# 빠른 시작 가이드 (Quick Start Guide)

## 📁 포트폴리오 구조

```
PORTFOLIO_AWS_IMDS_ATTACK/
├── README.md                          # 프로젝트 전체 개요
├── QUICK_START.md                     # 이 파일 (빠른 시작 가이드)
├── docs/
│   ├── 01_ATTACK_METHODOLOGY.md       # 공격 방법론 (8단계 상세)
│   ├── 02_TECHNICAL_ANALYSIS.md       # 기술적 분석 (취약점 상세)
│   ├── 03_DEFENSE_RECOMMENDATIONS.md  # 방어 권장사항
│   └── 04_LESSONS_LEARNED.md          # 학습 내용 및 인사이트
├── exploits/
│   ├── 135_tor_rotation_attack.py     # Tor IP 순환 공격
│   ├── 140_tor_attack_via_file.py     # 파일 기반 명령 실행
│   ├── 142_final_attack.py            # 최종 공격 스크립트
│   └── 143_oneliner_takeover.sh       # 서버 장악 스크립트
├── recovery/
│   ├── RECOVERY_GUIDE.md              # 복구 가이드 (상세)
│   └── EMERGENCY_RECOVERY.sh          # 긴급 복구 스크립트
├── credentials/
│   └── aws_stolen_*.sh                # 탈취한 AWS Credentials
└── screenshots/
    └── (공격 과정 스크린샷)
```

---

## 🚀 서버 복구 방법 (긴급!)

### 현재 서버 상태
- ❌ 웹사이트 변조됨 (접속 안됨)
- ❌ 백도어 설치됨
- ❌ 보안 시스템 무력화됨

### 복구 방법 (선택하세요)

#### 방법 1: 자동 복구 스크립트 사용 (권장)

**1. 서버에 SSH 접속**:
```bash
# 로컬에서
ssh ec2-user@3.35.22.248
# (키 인증 필요)

# 또는 백도어 사용자로 (비밀번호: Adm1n!2024#Secure)
ssh sysadmin@3.35.22.248
```

**2. 복구 스크립트 생성**:
```bash
cat > /tmp/EMERGENCY_RECOVERY.sh << 'EOF'
#!/bin/bash
echo "╔═══════════════════════════════════════════════╗"
echo "║   긴급 서버 복구 시작                        ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# 1. 백도어 제거
echo "[1/6] 백도어 제거 중..."
sudo userdel -r sysadmin 2>/dev/null
sudo rm -f /etc/sudoers.d/sysadmin
sudo crontab -r 2>/dev/null
sudo rm -f /usr/local/bin/backdoor_keeper.sh
echo "  ✅ 백도어 제거 완료"
echo ""

# 2. 웹쉘 제거
echo "[2/6] 웹쉘 제거 중..."
sudo rm -f /var/www/html/www/api/health.php
sudo find /var/www/html/www -name ".htaccess" -delete
echo "  ✅ 웹쉘 제거 완료"
echo ""

# 3. 웹사이트 복구
echo "[3/6] 웹사이트 복구 중..."
sudo cat > /var/www/html/www/index.php << 'EOFINDEX'
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>서비스 복구 완료</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }
        .container {
            background: white;
            padding: 3rem;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
        }
        h1 { color: #2ecc71; }
    </style>
</head>
<body>
    <div class="container">
        <h1>✅ 서비스가 정상적으로 복구되었습니다</h1>
        <p>보안 취약점이 제거되고 시스템이 안전하게 복구되었습니다.</p>
    </div>
</body>
</html>
EOFINDEX

sudo cat > /var/www/html/www/api/health.php << 'EOFHEALTH'
<?php
header('Content-Type: application/json');
echo json_encode(['status' => 'OK', 'timestamp' => time()]);
?>
EOFHEALTH

sudo chown -R apache:apache /var/www/html/www
echo "  ✅ 웹사이트 복구 완료"
echo ""

# 4. Apache 재시작
echo "[4/6] Apache 재시작 중..."
sudo apachectl configtest && sudo systemctl restart httpd
echo "  ✅ Apache 재시작 완료"
echo ""

# 5. Splunk 복구
echo "[5/6] Splunk 복구 중..."
sudo chmod 755 /opt/splunk/bin/splunk 2>/dev/null
sudo systemctl start Splunkd 2>/dev/null
echo "  ✅ Splunk 복구 완료"
echo ""

# 6. 검증
echo "[6/6] 복구 검증 중..."
if ! id sysadmin &>/dev/null; then
    echo "  ✅ 백도어 제거 확인"
else
    echo "  ❌ 백도어 여전히 존재"
fi

if curl -s http://localhost/ | grep -q "정상적으로 복구"; then
    echo "  ✅ 웹사이트 정상"
else
    echo "  ⚠️  웹사이트 상태 확인 필요"
fi

if systemctl is-active --quiet httpd; then
    echo "  ✅ Apache 정상 작동"
else
    echo "  ❌ Apache 작동 안함"
fi

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║   ✅ 복구 완료!                              ║"
echo "╚═══════════════════════════════════════════════╝"
EOF

chmod +x /tmp/EMERGENCY_RECOVERY.sh
```

**3. 실행**:
```bash
bash /tmp/EMERGENCY_RECOVERY.sh
```

#### 방법 2: 수동 복구 (단계별)

```bash
# 1. 백도어 제거
sudo userdel -r sysadmin
sudo rm -f /etc/sudoers.d/sysadmin
sudo crontab -r
sudo rm -f /usr/local/bin/backdoor_keeper.sh

# 2. 웹사이트 복구
sudo rm -f /var/www/html/www/index.php
sudo rm -f /var/www/html/www/api/health.php
sudo find /var/www/html/www -name ".htaccess" -delete

# 3. Apache 재시작
sudo systemctl restart httpd

# 4. Splunk 복구
sudo chmod 755 /opt/splunk/bin/splunk
sudo systemctl start Splunkd
```

---

## 📖 문서 읽는 순서 (포트폴리오 리뷰용)

### 1. 전체 개요 파악
📄 `README.md` 먼저 읽기
- 프로젝트 목표
- 공격 타임라인
- 달성 성과
- 핵심 교훈

### 2. 공격 방법론 이해
📄 `docs/01_ATTACK_METHODOLOGY.md`
- Phase 1: 정찰
- Phase 2: 익명화 (Tor)
- Phase 3: SSRF 취약점 발견
- Phase 4: AWS Credentials 탈취
- Phase 5: 시스템 침투
- Phase 6: 권한 상승
- Phase 7: 영구성 확보
- Phase 8: 보안 시스템 무력화

### 3. 기술적 분석
📄 `docs/02_TECHNICAL_ANALYSIS.md`
- 취약점 상세 분석 (CVSS 점수 포함)
- 공격 표면 분석
- 보안 아키텍처 리뷰
- 위험도 평가

### 4. 방어 전략
📄 `docs/03_DEFENSE_RECOMMENDATIONS.md`
- 즉시 조치 (24시간 내)
- 단기/중기/장기 조치
- 모니터링 및 탐지
- 인시던트 대응 절차

### 5. 학습 내용 및 인사이트
📄 `docs/04_LESSONS_LEARNED.md`
- **중요!** 초기 실패 → 취약점 설정 → 공격 성공 과정
- Red Team 관점
- Blue Team 관점
- 핵심 교훈
- 실무 적용 방안

---

## 🎯 핵심 메시지

> **"Perfect Security + One Small Gap = Total Compromise"**

이 프로젝트는 완벽해 보이는 보안 시스템도, 단 하나의 작은 허점이
전체 시스템의 완전한 장악으로 이어질 수 있음을 증명합니다.

### 초기 상황
✅ ModSecurity WAF 활성화
✅ Splunk SIEM 모니터링
✅ PHP 함수 제한
✅ SSH 키 인증

### 취약점 2개 설정
❌ health.php WAF 예외
❌ IMDSv1 활성화

### 결과
🔴 전체 시스템 완전 장악

---

## 💡 주요 학습 내용

### 1. 보안 예외의 위험성
```apache
# 이 한 줄이 전체 시스템을 무너뜨림
<LocationMatch "/api/health\.php">
    SecRuleEngine Off
</LocationMatch>
```

### 2. 레거시 프로토콜의 위험성
- IMDSv1 → SSRF로 Credentials 탈취 가능
- IMDSv2 → Session Token 필요, SSRF 방어

### 3. 공격 체인의 위력
```
SSRF → IMDSv1 → Credentials → 웹쉘 → 백도어 → Root → Splunk 무력화
```

### 4. 영구성 확보의 중요성
- Cron을 통한 자동 복구
- 다중 백도어 (SSH + 웹쉘 + AWS)
- 5분마다 자동 재생성

---

## 📊 프로젝트 성과

| 목표 | 상태 | 방법 |
|------|------|------|
| 익명 접근 | ✅ | Tor IP 순환 |
| SSRF 활용 | ✅ | health.php 취약점 |
| AWS Credentials | ✅ | IMDSv1 탈취 |
| 웹사이트 변조 | ✅ | Matrix 해킹 페이지 |
| 백도어 사용자 | ✅ | sysadmin (sudo NOPASSWD) |
| Splunk 무력화 | ✅ | 프로세스 종료 |
| 영구 백도어 | ✅ | Cron 자동 복구 |
| Root 권한 | ✅ | sudo su - |

**총 소요 시간**: 약 90분
**성공률**: 100% (취약점 설정 후)

---

## 🛠️ 사용된 기술

### 공격 도구
- Python 3 (requests, stem, pysocks)
- Tor (익명화)
- AWS CLI & boto3
- Bash scripting
- PHP (웹쉘)

### 공격 기법
- SSRF (Server-Side Request Forgery)
- AWS IMDSv1 Exploitation
- WAF Bypass (ModSecurity 예외 악용)
- Tor Network (IP 순환)
- Privilege Escalation (sudo NOPASSWD)
- Persistence (Cron 자동 복구)

---

## ⚠️ 법적 고지

이 프로젝트는 **승인된 환경**에서 **교육 목적**으로 수행되었습니다.

- ✅ 자체 소유 AWS 환경
- ✅ 테스트 목적의 격리된 시스템
- ✅ 의도적으로 설정한 취약점
- ✅ 모든 활동 기록 및 복구 계획 수립

**무단으로 타인의 시스템을 공격하는 것은 불법입니다.**

---

## 📞 다음 단계

### 즉시
1. ✅ 서버 복구 실행
2. ✅ 웹사이트 접근 테스트
3. ✅ 백도어 제거 확인

### 단기
1. 보안 설정 강화 (IMDSv2, WAF)
2. 로그 분석 실시
3. 침해 범위 확인

### 장기
1. Red/Blue Team 훈련
2. 보안 정책 재검토
3. 제로 트러스트 아키텍처 검토

---

## 📚 추가 자료

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [AWS IMDSv2 Migration Guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [ModSecurity Core Rule Set](https://coreruleset.org/)

---

**포트폴리오 작성일**: 2025-11-17
**환경**: AWS EC2 (Amazon Linux 2)
**목적**: Red Team Penetration Testing Portfolio

---

**끝.**
