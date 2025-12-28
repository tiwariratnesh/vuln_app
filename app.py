#!/usr/bin/env python3
"""
Comprehensive Vulnerable Application for Exploitability Testing
Contains REACHABLE and NON-REACHABLE vulnerabilities across:
- Code (SAST): SQL Injection, Command Injection, XSS
- Packages (SCA): CVEs in dependencies
- Image: Vulnerable base image packages
"""
from flask import Flask, request, render_template_string
import sqlite3
import os
import subprocess
import yaml
import pickle
import requests
import jwt
from cryptography.fernet import Fernet
import paramiko

app = Flask(__name__)

# ============================================================================
# REACHABLE CODE VULNERABILITIES (SAST)
# ============================================================================

@app.route('/api/login', methods=['POST'])
def login_vulnerable():
    """SQL INJECTION - REACHABLE via POST /api/login"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    # VULN: SQL Injection (directly concatenating user input)
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {"status": "success", "user": user[0]}
    return {"status": "failed"}, 401

@app.route('/api/search', methods=['GET'])
def search_vulnerable():
    """XSS - REACHABLE via GET /api/search?q=<script>"""
    search_query = request.args.get('q', '')
    
    # VULN: Reflected XSS (no sanitization)
    html = f"""
    <html>
        <body>
            <h1>Search Results for: {search_query}</h1>
            <p>No results found</p>
        </body>
    </html>
    """
    return render_template_string(html)

@app.route('/api/exec', methods=['POST'])
def exec_vulnerable():
    """COMMAND INJECTION - REACHABLE via POST /api/exec"""
    command = request.form.get('cmd', 'ls')
    
    # VULN: Command Injection (shell=True with user input)
    try:
        result = subprocess.check_output(f"echo Result: {command}", shell=True, text=True)
        return {"output": result}
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/api/config', methods=['POST'])
def yaml_load_vulnerable():
    """YAML DESERIALIZATION - REACHABLE via POST /api/config"""
    config_data = request.data
    
    # VULN: Unsafe YAML deserialization (yaml.load without Loader)
    try:
        config = yaml.load(config_data, Loader=yaml.Loader)
        return {"config": str(config)}
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/api/session', methods=['POST'])
def pickle_vulnerable():
    """INSECURE DESERIALIZATION - REACHABLE via POST /api/session"""
    session_data = request.data
    
    # VULN: Pickle deserialization (allows code execution)
    try:
        session = pickle.loads(session_data)
        return {"session": str(session)}
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/api/proxy', methods=['GET'])
def ssrf_vulnerable():
    """SSRF - REACHABLE via GET /api/proxy?url=http://169.254.169.254/latest/meta-data/"""
    url = request.args.get('url', '')
    
    # VULN: Server-Side Request Forgery (no URL validation)
    try:
        response = requests.get(url, timeout=5)
        return {"content": response.text, "status": response.status_code}
    except Exception as e:
        return {"error": str(e)}, 500

# ============================================================================
# NON-REACHABLE CODE VULNERABILITIES (SAST - DEAD CODE)
# ============================================================================

def admin_backdoor_unreachable(user_input):
    """PATH TRAVERSAL - NOT REACHABLE (no route calls this)"""
    # VULN: Path Traversal (but never called)
    file_path = f"/var/data/{user_input}"
    with open(file_path, 'r') as f:
        return f.read()

def debug_shell_unreachable(cmd):
    """COMMAND INJECTION - NOT REACHABLE (internal debug function)"""
    # VULN: Command injection (but never exposed via API)
    return os.system(cmd)

def decrypt_secret_unreachable(encrypted_data):
    """WEAK CRYPTO - NOT REACHABLE (unused helper)"""
    # VULN: Hardcoded encryption key (but function never called)
    key = b'insecure_key_1234567890123456'
    f = Fernet(key)
    return f.decrypt(encrypted_data)

# ============================================================================
# REACHABLE DEPENDENCY VULNERABILITIES (SCA)
# ============================================================================

@app.route('/api/jwt-decode', methods=['POST'])
def jwt_decode_vulnerable():
    """Uses PyJWT with known CVEs - REACHABLE"""
    token = request.form.get('token', '')
    
    # Uses vulnerable PyJWT library
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return {"payload": decoded}
    except Exception as e:
        return {"error": str(e)}, 500

@app.route('/api/ssh-connect', methods=['POST'])
def ssh_vulnerable():
    """Uses Paramiko with known CVEs - REACHABLE"""
    host = request.form.get('host', 'localhost')
    
    # Uses vulnerable Paramiko library
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return {"status": "ssh client initialized"}
    except Exception as e:
        return {"error": str(e)}, 500

# ============================================================================
# NON-REACHABLE DEPENDENCY VULNERABILITIES (SCA - DEAD CODE)
# ============================================================================

def unused_crypto_function():
    """Uses cryptography lib - NOT REACHABLE (never called)"""
    # Cryptography package might have CVEs, but this function is never used
    key = Fernet.generate_key()
    return Fernet(key)

def unused_yaml_parser(data):
    """Uses PyYAML - NOT REACHABLE (duplicate, unused function)"""
    # PyYAML might have CVEs, but this specific function is never called
    return yaml.safe_load(data)

# ============================================================================
# HEALTH CHECK (SAFE ENDPOINT)
# ============================================================================

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint - SAFE"""
    return {"status": "healthy", "version": "1.0.0"}

@app.route('/', methods=['GET'])
def index():
    """Index page - SAFE"""
    return {
        "app": "Exploitability Test Application",
        "endpoints": {
            "reachable_vulnerable": [
                "POST /api/login - SQL Injection",
                "GET /api/search - XSS",
                "POST /api/exec - Command Injection",
                "POST /api/config - YAML Deserialization",
                "POST /api/session - Pickle Deserialization",
                "GET /api/proxy - SSRF",
                "POST /api/jwt-decode - Vulnerable JWT lib",
                "POST /api/ssh-connect - Vulnerable SSH lib"
            ],
            "safe": [
                "GET /health",
                "GET /"
            ]
        },
        "note": "This app contains intentional vulnerabilities for testing"
    }

if __name__ == '__main__':
    # Initialize database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                     (username TEXT, password TEXT, role TEXT)''')
    cursor.execute("INSERT OR IGNORE INTO users VALUES ('admin', 'admin123', 'admin')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES ('user', 'pass123', 'user')")
    conn.commit()
    conn.close()
    
    # Run app
    app.run(host='0.0.0.0', port=5000, debug=False)

