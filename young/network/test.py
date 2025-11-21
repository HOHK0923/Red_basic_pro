#!/usr/bin/env python3
import sys
import subprocess

print("=== Scapy Diagnostic Tool ===\n")

# Python 버전 확인
print(f"Python version: {sys.version}")

# Scapy 설치 확인
try:
    import scapy
    print(f"Scapy version: {scapy.__version__}")
    print(f"Scapy location: {scapy.__file__}")
except ImportError:
    print("Scapy is not installed!")
    sys.exit(1)

# 각 모듈 테스트
modules_to_test = [
    "scapy.all",
    "scapy.layers.inet",
    "scapy.layers.dns",
    "scapy.layers.l2"
]

for module in modules_to_test:
    try:
        __import__(module)
        print(f"✓ {module} - OK")
    except ImportError as e:
        print(f"✗ {module} - Error: {e}")

# 실제 클래스 import 테스트
print("\nTesting specific imports:")
try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, ARP, Ether
    print("✓ All imports successful!")
    
    # 버전별 차이 확인
    print(f"\nAvailable attributes in scapy.all:")
    import scapy.all
    dns_related = [attr for attr in dir(scapy.all) if 'DNS' in attr]
    print(f"DNS related: {dns_related}")
    
except ImportError as e:
    print(f"✗ Import error: {e}")