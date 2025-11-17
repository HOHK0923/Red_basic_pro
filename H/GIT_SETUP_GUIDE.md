# GitHub Repository 연결 가이드

## 1. GitHub에서 새 Repository 생성

1. https://github.com/new 접속
2. Repository name: `AWS-IMDS-Attack-Chain`
3. Description: `AWS IMDSv1 취약점 공격 체인 - 보안 멘토링 프로젝트`
4. Public 선택
5. **Initialize this repository with a README 체크 해제** (이미 로컬에 있음)
6. Create repository 클릭

## 2. 로컬 저장소와 연결

터미널에서 다음 명령어 실행:

\`\`\`bash
cd /Users/hwangjunha/Desktop/Red_basic_local/H/CLEAN_PROJECT

# 원격 저장소 연결
git remote add origin https://github.com/HOHK0923/AWS-IMDS-Attack-Chain.git

# branch 이름을 main으로 변경
git branch -M main

# Push
git push -u origin main
\`\`\`

## 3. 완료 확인

https://github.com/HOHK0923/AWS-IMDS-Attack-Chain 에서 확인

## 현재 상태

- ✅ Git repository 초기화 완료
- ✅ 첫 커밋 완료
- ⏳ GitHub 원격 저장소 연결 대기 중

## 파일 목록

\`\`\`
CLEAN_PROJECT/
├── 01_AWS_IMDS_Attack/
│   ├── 119_setup_aws_vuln.sh
│   ├── 120_aws_imds_exploit.py
│   ├── 121_aws_privilege_escalation.py
│   └── 122_aws_ssm_command.py
├── 02_Site_Defacement/
│   ├── TOGGLE_SILENT.sh
│   └── SILENT_DOWNLOAD.sh
├── 03_Documentation/
│   └── COMPLETE_ATTACK_ANALYSIS.md
└── README.md
\`\`\`
