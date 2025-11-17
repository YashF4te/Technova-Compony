# app.py
"""
Technova — Cybersecurity Infrastructure (Streamlit demo)

Single-file Streamlit app that provides:
- User & Role Management (PBKDF2 password hashing)
- Asset Inventory
- Secrets Manager (Fernet encryption)
- Simple File Scanner (detects common secret patterns)
- Dependency Vulnerability Checker (simulated)
- Incident Response checklist & evidence uploads
- Audit logging (SQLite)
"""

import streamlit as st
import sqlite3
import os
import time
import base64
import hashlib
import hmac
import secrets
from datetime import datetime
from typing import Optional, Tuple, List, Dict
from cryptography.fernet import Fernet

# -------------------------
# Configuration & Helpers
# -------------------------
APP_TITLE = "Technova — Cybersecurity Infrastructure"
DB_PATH = "infra.db"
UPLOAD_DIR = "evidence_uploads"
MASTER_KEY_PATH = "master.key"

os.makedirs(UPLOAD_DIR, exist_ok=True)

st.set_page_config(APP_TITLE, layout="wide")

# -------------------------
# Master key / Fernet setup
# -------------------------
def load_or_create_master_key(path: str = MASTER_KEY_PATH) -> bytes:
    if os.path.exists(path):
        with open(path, "rb") as fh:
            return fh.read().strip()
    else:
        key = Fernet.generate_key()
        with open(path, "wb") as fh:
            fh.write(key)
        return key

MASTER_KEY = load_or_create_master_key()
FERNET = Fernet(MASTER_KEY)

# -------------------------
# Database init
# -------------------------
def init_db(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        salt BLOB,
        pwd_hash BLOB,
        role TEXT,
        created_at INTEGER
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY,
        name TEXT,
        ip_or_host TEXT,
        owner TEXT,
        tags TEXT,
        created_at INTEGER
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY,
        name TEXT,
        encrypted_value BLOB,
        meta TEXT,
        created_at INTEGER
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY,
        title TEXT,
        severity TEXT,
        status TEXT,
        notes TEXT,
        created_at INTEGER
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audits (
        id INTEGER PRIMARY KEY,
        actor TEXT,
        action TEXT,
        details TEXT,
        ts INTEGER
    )
    """)
    conn.commit()

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    init_db(conn)
    return conn

CONN = get_conn()

# -------------------------
# Security primitives
# -------------------------
def pbkdf2_hash(password: str, salt: Optional[bytes] = None, iterations: int = 200_000) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = secrets.token_bytes(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=32)
    return salt, pwd_hash

def verify_password(password: str, salt: bytes, pwd_hash: bytes, iterations: int = 200_000) -> bool:
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=32)
    return hmac.compare_digest(candidate, pwd_hash)

def log_event(actor: str, action: str, details: str = ""):
    ts = int(time.time())
    cur = CONN.cursor()
    cur.execute("INSERT INTO audits (actor, action, details, ts) VALUES (?, ?, ?, ?)",
                (actor, action, details, ts))
    CONN.commit()

# -------------------------
# User management
# -------------------------
def create_user(username: str, password: str, role: str = "user") -> bool:
    cur = CONN.cursor()
    salt, pwd_hash = pbkdf2_hash(password)
    try:
        cur.execute("INSERT INTO users (username, salt, pwd_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                    (username, salt, pwd_hash, role, int(time.time())))
        CONN.commit()
        log_event("system", "create_user", f"user={username}, role={role}")
        return True
    except sqlite3.IntegrityError:
        return False

def authenticate(username: str, password: str) -> Optional[Dict]:
    cur = CONN.cursor()
    cur.execute("SELECT id, username, salt, pwd_hash, role FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    if not row:
        return None
    uid, uname, salt, pwd_hash, role = row
    if verify_password(password, salt, pwd_hash):
        log_event(uname, "login", "success")
        return {"id": uid, "username": uname, "role": role}
    else:
        log_event(uname, "login", "failed")
        return None

def ensure_admin_exists():
    cur = CONN.cursor()
    cur.execute("SELECT COUNT(1) FROM users")
    (count,) = cur.fetchone()
    if count == 0:
        # create default admin with random strong password and show it once
        default_admin = "admin"
        pw = base64.urlsafe_b64encode(secrets.token_bytes(12)).decode()
        create_user(default_admin, pw, role="admin")
        return default_admin, pw
    return None, None

# -------------------------
# Asset inventory
# -------------------------
def add_asset(name: str, host: str, owner: str, tags: str):
    cur = CONN.cursor()
    cur.execute("INSERT INTO assets (name, ip_or_host, owner, tags, created_at) VALUES (?, ?, ?, ?, ?)",
                (name, host, owner, tags, int(time.time())))
    CONN.commit()
    log_event("system", "add_asset", f"{name} ({host}) owner={owner}")

def list_assets() -> List[Tuple]:
    cur = CONN.cursor()
    cur.execute("SELECT id, name, ip_or_host, owner, tags, created_at FROM assets ORDER BY created_at DESC")
    return cur.fetchall()

# -------------------------
# Secrets manager
# -------------------------
def store_secret(name: str, value: bytes, meta: str = ""):
    token = FERNET.encrypt(value)
    cur = CONN.cursor()
    cur.execute("INSERT INTO secrets (name, encrypted_value, meta, created_at) VALUES (?, ?, ?, ?)",
                (name, token, meta, int(time.time())))
    CONN.commit()
    log_event("system", "store_secret", f"{name}")

def get_secrets() -> List[Tuple]:
    cur = CONN.cursor()
    cur.execute("SELECT id, name, encrypted_value, meta, created_at FROM secrets ORDER BY created_at DESC")
    return cur.fetchall()

def decrypt_token(token: bytes) -> bytes:
    return FERNET.decrypt(token)

# -------------------------
# Incidents
# -------------------------
def create_incident(title: str, severity: str, status: str, notes: str):
    cur = CONN.cursor()
    cur.execute("INSERT INTO incidents (title, severity, status, notes, created_at) VALUES (?, ?, ?, ?, ?)",
                (title, severity, status, notes, int(time.time())))
    CONN.commit()
    log_event("system", "create_incident", f"{title} severity={severity}")

def list_incidents() -> List[Tuple]:
    cur = CONN.cursor()
    cur.execute("SELECT id, title, severity, status, notes, created_at FROM incidents ORDER BY created_at DESC")
    return cur.fetchall()

# -------------------------
# File scanner (simple heuristics)
# -------------------------
SUSPICIOUS_PATTERNS = [
    "PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY",
    "aws_access_key_id", "aws_secret_access_key", "AKIA",
    "password=", "passwd=", "secret=", "ssh-rsa", "ssh-dss",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----"
]

def scan_bytes_for_secrets(blob: bytes) -> List[str]:
    txt = None
    try:
        txt = blob.decode(errors="ignore")
    except Exception:
        txt = str(blob)
    found = []
    for p in SUSPICIOUS_PATTERNS:
        if p.lower() in txt.lower():
            found.append(p)
    return found

# -------------------------
# Dependency vuln scanner (SIMULATED)
# -------------------------
# This is a simulated local check. In production you'd query OSV/NVD, package feeds, etc.
SIMULATED_VULN_DB = {
    "flask": ["1.0", "1.1"],   # pretend older versions are vulnerable
    "django": ["2.2", "3.0"],
    "requests": ["2.19", "2.20"]
}

def parse_requirements_txt(text: str) -> List[Tuple[str, Optional[str]]]:
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
    out = []
    for l in lines:
        if "==" in l:
            pkg, ver = l.split("==", 1)
            out.append((pkg.strip().lower(), ver.strip()))
        else:
            out.append((l.strip().lower(), None))
    return out

def simulated_vuln_check(requirements_text: str) -> List[Tuple[str, str]]:
    parsed = parse_requirements_txt(requirements_text)
    findings = []
    for pkg, ver in parsed:
        bad_versions = SIMULATED_VULN_DB.get(pkg)
        if bad_versions:
            if ver is None or any(ver.startswith(bv) for bv in bad_versions):
                findings.append((pkg, f"Simulated vulnerable version: {ver or 'unspecified'}"))
    return findings

# -------------------------
# Utility displays
# -------------------------
def ts_to_str(ts: int) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

# -------------------------
# Ensure admin exists and show one-time password
# -------------------------
one_time_admin, one_time_pw = ensure_admin_exists()

# -------------------------
# Streamlit UI layout
# -------------------------
st.title(APP_TITLE)
st.markdown("Secure operations & infrastructure management demo for **Technova**.")
st.sidebar.header("Login / Controls")

# Simple session-state auth
if "user" not in st.session_state:
    st.session_state.user = None

# Login form or show user info
if st.session_state.user is None:
    with st.sidebar.form("login_form"):
        st.write("### Sign in")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Log in")
        if submitted:
            u = authenticate(username.strip(), password.strip())
            if u:
                st.session_state.user = u
                st.experimental_rerun()
            else:
                st.sidebar.error("Invalid credentials")
    if one_time_admin:
        st.sidebar.info(f"Default admin created: **{one_time_admin}** with password **{one_time_pw}**. Change it immediately.")
else:
    u = st.session_state.user
    st.sidebar.write(f"Signed in as **{u['username']}** ({u['role']})")
    if st.sidebar.button("Log out"):
        log_event(u["username"], "logout")
        st.session_state.user = None
        st.experimental_rerun()

# -------------------------
# Main tabs
# -------------------------
tabs = st.tabs(["Dashboard", "Users", "Assets", "Secrets", "Scan", "Incidents", "Audit Logs", "Admin"])

# ---------- Dashboard ----------
with tabs[0]:
    st.header("Overview Dashboard")
    # Basic metrics from DB
    cur = CONN.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    users_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM assets")
    assets_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM secrets")
    secrets_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM incidents")
    incidents_count = cur.fetchone()[0]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Users", users_count)
    c2.metric("Assets", assets_count)
    c3.metric("Secrets stored", secrets_count)
    c4.metric("Incidents", incidents_count)

    st.markdown("### Recent audit events")
    cur.execute("SELECT actor, action, details, ts FROM audits ORDER BY ts DESC LIMIT 10")
    rows = cur.fetchall()
    if rows:
        for r in rows:
            st.write(f"- {ts_to_str(r[3])} — **{r[0]}** {r[1]} — {r[2]}")
    else:
        st.write("No audit logs yet.")

# ---------- Users ----------
with tabs[1]:
    st.header("User Management")
    if st.session_state.user and st.session_state.user["role"] == "admin":
        st.subheader("Create user")
        with st.form("create_user"):
            uname = st.text_input("Username")
            pw = st.text_input("Password", type="password")
            role = st.selectbox("Role", ["user", "admin"])
            ok = st.form_submit_button("Create user")
            if ok:
                if not uname or not pw:
                    st.error("Provide username and password")
                else:
                    if create_user(uname.strip(), pw.strip(), role=role):
                        st.success("User created")
                    else:
                        st.error("User exists")
        st.subheader("All users")
        cur = CONN.cursor()
        cur.execute("SELECT id, username, role, created_at FROM users ORDER BY created_at DESC")
        users = cur.fetchall()
        for urow in users:
            st.write(f"- {urow[1]} ({urow[2]}) — created {ts_to_str(urow[3])}")
    else:
        st.info("Admin-only section. Contact admin to manage users.")

# ---------- Assets ----------
with tabs[2]:
    st.header("Asset Inventory")
    st.subheader("Add Asset")
    with st.form("add_asset"):
        aname = st.text_input("Asset name (e.g., web-server-1)")
        host = st.text_input("IP or hostname")
        owner = st.text_input("Owner / Team")
        tags = st.text_input("Tags (comma separated)")
        submit = st.form_submit_button("Add asset")
        if submit:
            if not aname or not host:
                st.error("Name and host required")
            else:
                add_asset(aname.strip(), host.strip(), owner.strip(), tags.strip())
                st.success("Asset added")

    st.subheader("List of assets")
    assets = list_assets()
    if assets:
        for a in assets:
            st.write(f"- **{a[1]}** — {a[2]} (owner: {a[3]}, tags: {a[4]}) added {ts_to_str(a[5])}")
    else:
        st.write("No assets recorded yet.")

# ---------- Secrets ----------
with tabs[3]:
    st.header("Secrets Manager")
    st.info("Secrets are encrypted with the app's master key. Keep the master key file secure.")

    if st.session_state.user and st.session_state.user["role"] == "admin":
        st.subheader("Store a secret")
        with st.form("store_secret"):
            sname = st.text_input("Secret name (e.g., db/password)")
            sval = st.text_area("Secret value (paste secrets)")
            meta = st.text_input("Meta (e.g., purpose or owner)")
            ok = st.form_submit_button("Store secret")
            if ok:
                if not sname or not sval:
                    st.error("Name and value required")
                else:
                    store_secret(sname.strip(), sval.encode(), meta)
                    st.success("Secret stored (encrypted)")

        st.subheader("Stored secrets (admin can decrypt)")
        secrets_rows = get_secrets()
        for s in secrets_rows:
            sid, name, token, meta, created_at = s
            st.write(f"- **{name}** (meta: {meta}) stored {ts_to_str(created_at)}")
            if st.button(f"Decrypt {name}", key=f"dec_{sid}"):
                try:
                    plaintext = decrypt_token(token)
                    st.code(plaintext.decode(errors="replace"))
                    log_event(st.session_state.user["username"], "decrypt_secret", name)
                except Exception as e:
                    st.error("Failed to decrypt")
    else:
        st.info("Admin-only. Request an admin to store/retrieve secrets.")

# ---------- Scan ----------
with tabs[4]:
    st.header("File Scanner & Dependency Checker")

    st.subheader("Upload file to scan for leaked secrets")
    f = st.file_uploader("Drop any file (logs, config, keys)", key="scan_file")
    if f:
        data = f.read()
        findings = scan_bytes_for_secrets(data)
        st.write(f"File size: {len(data)} bytes")
        if findings:
            st.error("Potential secrets found:")
            for p in findings:
                st.write(f"- {p}")
            # save evidence
            evidence_path = os.path.join(UPLOAD_DIR, f"{int(time.time())}_{f.name}")
            with open(evidence_path, "wb") as fh:
                fh.write(data)
            st.success(f"Saved evidence to {evidence_path}")
            log_event(st.session_state.user["username"] if st.session_state.user else "anonymous", "scan_found", f"{f.name} -> {findings}")
        else:
            st.success("No suspicious patterns detected.")

    st.subheader("Upload requirements.txt to run a simulated vulnerability check")
    req = st.file_uploader("requirements.txt", key="reqs")
    if req:
        txt = req.read().decode(errors="ignore")
        findings = simulated_vuln_check(txt)
        if findings:
            st.warning("Simulated vulnerable packages found:")
            for p, desc in findings:
                st.write(f"- {p}: {desc}")
            log_event(st.session_state.user["username"] if st.session_state.user else "anonymous", "vuln_scan", str(findings))
        else:
            st.success("No simulated vulns detected in uploaded requirements.")

    st.markdown("**Note:** For production use, integrate with real vulnerability feeds (OSV, NVD) and SBOM.")

# ---------- Incidents ----------
with tabs[5]:
    st.header("Incident Response")

    st.subheader("Create Incident")
    with st.form("create_inc"):
        title = st.text_input("Title")
        severity = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"])
        notes = st.text_area("Notes / initial triage")
        ok = st.form_submit_button("Create incident")
        if ok:
            if not title:
                st.error("Provide a title")
            else:
                create_incident(title, severity, "Open", notes)
                st.success("Incident created")

    st.subheader("Active incidents")
    incidents = list_incidents()
    if incidents:
        for inc in incidents:
            st.write(f"- **{inc[1]}** severity={inc[2]} status={inc[3]} created {ts_to_str(inc[5])}")
            if st.button(f"Mark Resolved {inc[0]}", key=f"res_{inc[0]}"):
                cur = CONN.cursor()
                cur.execute("UPDATE incidents SET status=? WHERE id=?", ("Resolved", inc[0]))
                CONN.commit()
                log_event(st.session_state.user["username"] if st.session_state.user else "anonymous", "resolve_incident", inc[1])
                st.experimental_rerun()
    else:
        st.write("No incidents logged.")

    st.subheader("Incident Response Checklist")
    st.markdown("""
    - Identify & contain incident
    - Collect evidence (upload files below)
    - Preserve logs & timeline
    - Notify stakeholders
    - Remediate & recover
    - Post-incident review
    """)

    st.file_uploader("Upload evidence (will be saved)", key="evidence_upload", on_change=None)
    # Save evidence if present (handle in the form above)
    # For simplicity the file uploader handling used in Scan keeps evidence

# ---------- Audit Logs ----------
with tabs[6]:
    st.header("Audit Log & Exports")
    cur = CONN.cursor()
    cur.execute("SELECT actor, action, details, ts FROM audits ORDER BY ts DESC LIMIT 200")
    rows = cur.fetchall()
    for r in rows:
        st.write(f"- {ts_to_str(r[3])} — **{r[0]}** {r[1]} — {r[2]}")

    st.subheader("Export logs (.csv)")
    if st.button("Download logs CSV"):
        cur.execute("SELECT actor, action, details, ts FROM audits ORDER BY ts DESC")
        all_rows = cur.fetchall()
        import csv, io
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["actor", "action", "details", "ts"])
        for rr in all_rows:
            w.writerow([rr[0], rr[1], rr[2], ts_to_str(rr[3])])
        st.download_button("⬇ Download CSV", buf.getvalue(), file_name="technova_audit_logs.csv", mime="text/csv")

# ---------- Admin ----------
with tabs[7]:
    st.header("Admin / Config")
    st.subheader("Master key (KEEP SECRET)")
    st.write("The application uses a locally stored master key for encryption. Save it securely. If lost, secrets cannot be recovered.")
    if st.session_state.user and st.session_state.user["role"] == "admin":
        with st.expander("Show master key (copy & store securely)"):
            st.code(MASTER_KEY.decode())
    else:
        st.info("Admin-only")

    st.subheader("Security utilities")
    st.markdown("**Password policy tester**")
    with st.form("pw_policy"):
        candidate = st.text_input("Test password", type="password")
        submit = st.form_submit_button("Test")
        if submit:
            reasons = []
            if len(candidate) < 12:
                reasons.append("Too short (min 12 chars recommended)")
            if candidate.lower() == candidate or candidate.upper() == candidate:
                reasons.append("Use a mix of upper and lower case")
            if not any(c.isdigit() for c in candidate):
                reasons.append("Include digits")
            if not any(not c.isalnum() for c in candidate):
                reasons.append("Include special characters")
            if reasons:
                st.error("Weak: " + "; ".join(reasons))
            else:
                st.success("Strong password (meets basic policy)")

    st.subheader("System info")
    st.write(f"- DB path: `{DB_PATH}`")
    st.write(f"- Upload dir: `{UPLOAD_DIR}`")
    st.write(f"- Number of audit rows: {CONN.execute('SELECT COUNT(1) FROM audits').fetchone()[0]}")

    st.markdown("---")
    st.markdown("**Caveats & Next steps**")
    st.markdown("""
    - This is a demo. For production: use KMS (AWS KMS, Azure Key Vault), hardened DB, RBAC + MFA, 
      SIEM integration (Splunk, Elastic), and vulnerability scanning services (OSV, NVD).
    - Replace local master key with secure key management.
    - Add rate-limiting, CSRF protections, and hardened session handling when exposing the app publicly.
    """)

# -------------------------
# End of app
# -------------------------
