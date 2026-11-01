import os
import sqlite3
import pickle
import hashlib
from flask import Flask, request

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded AWS Secret Key
AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"
DATABASE_URL = "postgres://admin:SuperSecretPassword123@prod-db.internal:5432/finance"

# VULNERABILITY 2: SQL Injection (Concatenation)
def get_user_profile(username):
    conn = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()

# VULNERABILITY 3: OS Command Injection (shell=True)
def ping_server(ip_address):
    # Attacker can supply '127.0.0.1; cat /etc/passwd'
    os.system("ping -c 1 " + ip_address)

# VULNERABILITY 4: Insecure Deserialization
def load_user_session(cookie_data):
    # Deserializing untrusted user input leads to arbitrary code execution
    return pickle.loads(cookie_data)

# VULNERABILITY 5: Broken Cryptographic Hash (MD5 for passwords)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABILITY 6: Security Misconfiguration (Debug mode enabled in production)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
