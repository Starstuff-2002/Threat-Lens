import boto3

# Demo Scenario 1: Hardcoded Secrets and SQL Injection

def connect_to_aws():
    # Oh no, the developer committed their access key directly into the code!
    aws_key = "AKIA1234567890ABCDEF"
    aws_secret = "super_secret_string"
    print("Connecting to AWS...")

def execute_db(query):
    # Dummy function to simulate database execution
    pass

def get_user_data(username):
    # Classic SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return execute_db(query)
