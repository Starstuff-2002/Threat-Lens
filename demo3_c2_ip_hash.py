import socket
import hashlib

# Demo Scenario 3: C2 Server IPs and Malware Hashes

def beacon_home():
    print("Initiating beacon to command and control server...")
    
    # This IP is hardcoded in the Go mock as a known malicious C2 server
    c2_server = "45.33.32.156"
    
    # Open socket to all interfaces (Risky Bind)
    bind_ip = "0.0.0.0"
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((bind_ip, 4444))

def verify_payload():
    # This hash is hardcoded in the Go mock as known ransomware
    expected_hash = "d41d8cd98f00b204e9800998ecf8427e"
    print(f"Verifying payload against known hash: {expected_hash}")
    
    # ... downloading logic ...
