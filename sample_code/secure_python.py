import os
import sqlite3
import json
import hashlib
import subprocess
from flask import Flask, request

app = Flask(__name__)

# SECURE 1: Loaded from protected environment variables
AWS_SECRET = os.getenv("AWS_ACCESS_KEY_ID")
DATABASE_URL = os.getenv("DATABASE_URL")

# SECURE 2: Parameterized SQL Query
def get_user_profile(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT id, username, email FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchall()

# SECURE 3: Safe Subprocess Execution without Shell
def ping_server(ip_address):
    # Verify input format or use shell=False with argument array
    subprocess.run(["ping", "-c", "1", ip_address], shell=False, check=True)

# SECURE 4: Safe Serialization with JSON
def load_user_session(cookie_data):
    return json.loads(cookie_data)

# SECURE 5: Strong Cryptographic Hashing with Salt (SHA-256 / PBKDF2)
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000).hex()

# SECURE 6: Debug disabled in production
if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    app.run(host="127.0.0.1", port=5000, debug=debug_mode)
