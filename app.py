# app.py
import os
import time
import json
import secrets
import re
from datetime import datetime, timedelta
from flask import Flask, request, render_template, jsonify, send_from_directory
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'storage'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('logs', exist_ok=True)

# ---- Simulated central SOC log file ----
CENTRAL_LOG = 'logs/central.log'

# ---- Simple in-memory IDS / DoS tracker ----
REQUEST_TRACKER = {}  # key: ip, value: list of timestamps
DOS_THRESHOLD = 10    # requests
DOS_WINDOW_SECONDS = 5

# ---- Simple MFA tokens (for demo) ----
MFA_TOKENS = {}  # session_id -> token (expire shortly)


# ---- Helper utilities ----
def write_log(entry: dict):
    entry['ts'] = datetime.utcnow().isoformat() + 'Z'
    with open(CENTRAL_LOG, 'a') as f:
        f.write(json.dumps(entry) + '\n')

def check_dlp(text: str):
    # basic DLP rule examples — block if certain keywords or patterns appear
    keywords = ['password', 'ssn', 'secret', 'confidential', 'credit card', 'api_key']
    for kw in keywords:
        if re.search(r'\b' + re.escape(kw) + r'\b', text, re.IGNORECASE):
            return True, f"Blocked by DLP rule: keyword '{kw}'"
    # example: block patterns of 4+ digits groups that might look like card numbers
    if re.search(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}\b', text):
        return True, "Blocked by DLP pattern: possible card/ID number"
    return False, ""

def simulate_vpn_encrypt(plaintext: bytes, key: bytes=None):
    # AESGCM 256-bit
    if key is None:
        key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return {
        'key': key.hex(),
        'nonce': nonce.hex(),
        'ciphertext': ct.hex()
    }

def simulate_vpn_decrypt(enc: dict):
    key = bytes.fromhex(enc['key'])
    nonce = bytes.fromhex(enc['nonce'])
    ct = bytes.fromhex(enc['ciphertext'])
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce, ct, associated_data=None)
        return pt
    except Exception as e:
        return None

def record_request(ip):
    now = time.time()
    lst = REQUEST_TRACKER.setdefault(ip, [])
    lst.append(now)
    # prune old
    cutoff = now - DOS_WINDOW_SECONDS
    REQUEST_TRACKER[ip] = [t for t in lst if t >= cutoff]
    return len(REQUEST_TRACKER[ip])

# ---- Routes ----

@app.route('/')
def index():
    # branches list for demo
    branches = ['Mumbai', 'Bengaluru', 'Hyderabad', 'Pune']
    return render_template('index.html', branches=branches)

@app.route('/request-mfa', methods=['POST'])
def request_mfa():
    session_id = secrets.token_urlsafe(8)
    token = f"{secrets.randbelow(999999):06d}"  # 6-digit OTP style
    MFA_TOKENS[session_id] = {
        'token': token,
        'expires': datetime.utcnow() + timedelta(minutes=5)
    }
    # In a real system OTP would be emailed/sent; here we return it so user can paste.
    write_log({'event': 'mfa_requested', 'session': session_id})
    return jsonify({'session': session_id, 'otp': token, 'note': 'This OTP is for demo only.'})

@app.route('/send', methods=['POST'])
def send():
    ip = request.remote_addr or 'local'
    cnt = record_request(ip)
    if cnt > DOS_THRESHOLD:
        write_log({'event': 'dos_detected', 'ip': ip, 'count': cnt})
        return jsonify({'ok': False, 'error': 'DoS/High-rate detected. Request blocked.'}), 429

    data = request.json
    src = data.get('src')
    dst = data.get('dst')
    content = data.get('content', '')
    session = data.get('session')
    otp = data.get('otp')

    # MFA check (mock)
    if session not in MFA_TOKENS:
        return jsonify({'ok': False, 'error': 'Invalid MFA session. Request an OTP first.'}), 401
    mrec = MFA_TOKENS[session]
    if datetime.utcnow() > mrec['expires']:
        return jsonify({'ok': False, 'error': 'OTP expired.'}), 401
    if otp != mrec['token']:
        write_log({'event': 'mfa_failed', 'session': session, 'src': src})
        return jsonify({'ok': False, 'error': 'Invalid OTP.'}), 401

    # DLP check
    blocked, reason = check_dlp(content)
    if blocked:
        write_log({'event': 'dlp_block', 'src': src, 'dst': dst, 'reason': reason})
        return jsonify({'ok': False, 'error': reason}), 403

    # Simulate VPN encryption
    enc = simulate_vpn_encrypt(content.encode('utf-8'))

    # Save to "encrypted storage" as if delivered to dst branch
    filename = f"{int(time.time())}_{src}_to_{dst}.json"
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    with open(path, 'w') as f:
        json.dump({'src': src, 'dst': dst, 'enc': enc}, f, indent=2)

    # Log to central SOC
    write_log({'event': 'file_sent', 'src': src, 'dst': dst, 'file': filename})

    # consume (delete) OTP after use
    del MFA_TOKENS[session]

    return jsonify({'ok': True, 'saved': filename})

@app.route('/central-logs', methods=['GET'])
def central_logs():
    if not os.path.exists(CENTRAL_LOG):
        return jsonify([])
    with open(CENTRAL_LOG, 'r') as f:
        lines = [json.loads(line) for line in f.readlines() if line.strip()]
    # show most recent 200
    return jsonify(lines[-200:])

@app.route('/storage/<path:fn>', methods=['GET'])
def get_storage(fn):
    # retrieve stored encrypted file (simulate branch receiving)
    return send_from_directory(app.config['UPLOAD_FOLDER'], fn, as_attachment=True)

@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    data = request.json
    filename = data.get('filename')
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(path):
        return jsonify({'ok': False, 'error': 'file not found'}), 404
    with open(path, 'r') as f:
        payload = json.load(f)
    enc = payload['enc']
    pt = simulate_vpn_decrypt(enc)
    if pt is None:
        write_log({'event': 'decrypt_failed', 'file': filename})
        return jsonify({'ok': False, 'error': 'decryption failed'}), 500
    write_log({'event': 'file_decrypted', 'file': filename})
    return jsonify({'ok': True, 'plaintext': pt.decode('utf-8')})

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
