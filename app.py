#!/usr/bin/env python3
"""
Comprehensive Vulnerable Application for SCA Reachability Testing
Features:
- REACHABLE CVEs in DIRECT dependencies (Flask, requests, PyJWT, cryptography, paramiko, PyYAML)
- REACHABLE CVEs in TRANSITIVE dependencies (urllib3, certifi, bcrypt, Werkzeug, Jinja2)
- UNREACHABLE CVEs in imported but unused packages (PIL, lxml, pickle5)
"""
from flask import Flask, request, render_template_string, jsonify
import requests
import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import paramiko
import yaml
import os

# UNREACHABLE IMPORTS - These packages have CVEs but are NEVER called in any code path
try:
    from PIL import Image  # pillow 8.3.2 - has CVEs but NEVER used
    import lxml.etree      # lxml 4.6.3 - has CVEs but NEVER used
    import pickle5         # pickle5 - has CVEs but NEVER used
    UNUSED_IMPORTS = True  # Just to prevent linter warnings
except ImportError:
    pass

app = Flask(__name__)

# ============================================================================
# REACHABLE ENDPOINTS USING DIRECT VULNERABLE DEPENDENCIES
# ============================================================================

@app.route('/api/proxy', methods=['GET'])
def ssrf_endpoint():
    """REACHABLE: Uses requests (CVE-2023-32681) + urllib3 (CVE-2021-33503) + certifi (CVE-2022-23491)"""
    url = request.args.get('url', 'https://httpbin.org/get')
    try:
        response = requests.get(url, timeout=5, verify=True)
        return jsonify({
            "status": "success",
            "url": url,
            "response_code": response.status_code,
            "content_length": len(response.text)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/jwt-decode', methods=['POST'])
def jwt_decode():
    """REACHABLE: Uses PyJWT==1.7.1 (CVE-2022-29217 - Key Confusion Attack)"""
    token = request.json.get('token', '')
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return jsonify({"payload": decoded, "library": "PyJWT==1.7.1"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/jwt-encode', methods=['POST'])
def jwt_encode():
    """REACHABLE: Creates JWT using vulnerable PyJWT"""
    payload = request.json.get('payload', {})
    secret = request.json.get('secret', 'default_secret')
    try:
        token = jwt.encode(payload, secret, algorithm='HS256')
        return jsonify({"token": token, "library": "PyJWT==1.7.1"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/encrypt', methods=['POST'])
def encrypt_data():
    """REACHABLE: Uses cryptography==3.4.8 (CVE-2023-23931, CVE-2023-38325)"""
    data = request.json.get('data', 'test data')
    try:
        key = Fernet.generate_key()
        f = Fernet(key)
        encrypted = f.encrypt(data.encode())
        return jsonify({
            "encrypted": encrypted.decode('latin-1'),
            "key": key.decode('latin-1'),
            "library": "cryptography==3.4.8"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/aes-encrypt', methods=['POST'])
def aes_encrypt():
    """REACHABLE: Uses cryptography low-level AES cipher"""
    data = request.json.get('data', 'sensitive data')
    try:
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_data = data.ljust(16)
        encrypted = encryptor.update(padded_data.encode()) + encryptor.finalize()
        return jsonify({
            "encrypted": encrypted.hex(),
            "library": "cryptography==3.4.8 (AES-CBC)"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/ssh-init', methods=['POST'])
def ssh_init():
    """REACHABLE: Uses paramiko==2.7.2 (CVE-2022-24302) + bcrypt (CVE-2024-5569) + pynacl"""
    host = request.json.get('host', 'example.com')
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        transport = paramiko.Transport((host, 22))
        return jsonify({
            "status": "ssh client initialized",
            "host": host,
            "library": "paramiko==2.7.2"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/config', methods=['POST'])
def yaml_parse():
    """REACHABLE: Uses PyYAML==5.4 (CVE-2020-14343, CVE-2021-4189)"""
    yaml_data = request.data.decode('utf-8')
    try:
        config = yaml.load(yaml_data, Loader=yaml.FullLoader)
        return jsonify({
            "config": str(config),
            "library": "PyYAML==5.4"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================================
# REACHABLE ENDPOINTS USING TRANSITIVE VULNERABLE DEPENDENCIES
# ============================================================================

@app.route('/api/render', methods=['POST'])
def render_template():
    """REACHABLE: Uses Jinja2==3.0.3 (CVE-2024-22195) - TRANSITIVE via Flask"""
    template_string = request.json.get('template', '<h1>{{ message }}</h1>')
    message = request.json.get('message', 'Hello World')
    try:
        rendered = render_template_string(template_string, message=message)
        return jsonify({
            "rendered": rendered,
            "library": "Jinja2==3.0.3 (transitive via Flask)"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/werkzeug-test', methods=['GET'])
def werkzeug_test():
    """REACHABLE: Uses Werkzeug==2.0.3 (CVE-2023-25577) - TRANSITIVE via Flask"""
    from werkzeug.security import generate_password_hash, check_password_hash
    password = request.args.get('password', 'test123')
    try:
        hashed = generate_password_hash(password)
        is_valid = check_password_hash(hashed, password)
        return jsonify({
            "hashed": hashed,
            "verified": is_valid,
            "library": "Werkzeug==2.0.3 (transitive via Flask)"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================================
# UNREACHABLE CODE WITH VULNERABLE DEPENDENCIES (DEAD CODE)
# ============================================================================

def unused_click_command():
    """UNREACHABLE: Imports click (CVE-2023-48055) but never called"""
    @click.command()
    @click.option('--name', default='World')
    def hello(name):
        click.echo(f'Hello {name}!')
    return hello

def unused_crypto_function():
    """UNREACHABLE: Uses cryptography but this function is never exposed"""
    key = Fernet.generate_key()
    cipher = Fernet(key)
    return cipher.encrypt(b"secret data")

def unused_paramiko_function():
    """UNREACHABLE: Imports paramiko but never called via any route"""
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    return ssh

def unused_yaml_function(data):
    """UNREACHABLE: Uses PyYAML but this specific function never called"""
    return yaml.safe_load(data)

# ============================================================================
# SAFE ENDPOINTS
# ============================================================================

@app.route('/', methods=['GET'])
def index():
    """Index page with API documentation"""
    return jsonify({
        "app": "SCA Reachability Test Application",
        "version": "2.0.0",
        "purpose": "Test SCA scanner with reachable/unreachable CVEs",
        "endpoints": {
            "reachable_direct": {
                "GET /api/proxy": "Uses requests (+ urllib3, certifi transitive)",
                "POST /api/jwt-decode": "Uses PyJWT",
                "POST /api/jwt-encode": "Uses PyJWT",
                "POST /api/encrypt": "Uses cryptography",
                "POST /api/aes-encrypt": "Uses cryptography (AES)",
                "POST /api/ssh-init": "Uses paramiko (+ bcrypt, pynacl transitive)",
                "POST /api/config": "Uses PyYAML"
            },
            "reachable_transitive": {
                "POST /api/render": "Uses Jinja2 (transitive via Flask)",
                "GET /api/werkzeug-test": "Uses Werkzeug (transitive via Flask)"
            },
            "safe": {
                "GET /": "This page",
                "GET /health": "Health check"
            }
        },
        "dependencies": {
            "direct_reachable": ["Flask", "requests", "PyJWT", "cryptography", "paramiko", "PyYAML"],
            "transitive_reachable": ["urllib3", "certifi", "Werkzeug", "Jinja2", "bcrypt", "pynacl"],
            "unreachable": ["click", "MarkupSafe", "itsdangerous"]
        }
    })

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "version": "2.0.0"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
