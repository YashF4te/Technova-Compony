import streamlit as st

# ---------------------- PAGE CONFIG ----------------------
st.set_page_config(
    page_title="Interactive TechNova Case Study",
    layout="wide",
)

st.markdown("<h1 style='text-align:center;'>📘 <b>TechNova Interactive Case Study</b></h1>", unsafe_allow_html=True)
st.write("---")

# ---------------------- SIDEBAR SEARCH ----------------------
search_query = st.sidebar.text_input("🔍 Search Case Study")
st.sidebar.write("---")

# ---------------------- CASE STUDY CONTENT ----------------------
content = {
    "1. Introduction": '''
**TechNova Solutions Pvt. Ltd.** is a mid-sized IT service provider in Mumbai with branches in 
Bengaluru, Hyderabad, and Pune.

Problems faced:
- Unauthorized access
- Data leakage
- Weak authentication
- Unsecured branch communication

A new security system and data protection strategy was developed.
''',

    "2. Objectives of the Security Plan": '''
- Protect company data
- Block unauthorized access
- Encrypt branch communication
- AI threat monitoring
- ISO 27001 & GDPR compliance
''',

    "3. Existing Security Challenges": '''
### 3.1 Network Vulnerabilities
- Basic routers
- No centralized monitoring

### 3.2 Weak Access Controls
- Password sharing
- No MFA
- Poor admin permissions

### 3.3 Unsecured Data Transfer
- Email sharing of files
- No VPN tunnels

### 3.4 Incident Response Gaps
- No SOC
- No log review
''',

    "4. Company-Wide Security System Plan": '''
### 4.1 Physical Security
- Biometrics
- AI CCTV
- RFID
- Fire suppression

### 4.2 Network Security
- NGFW Firewall
- IDS/IPS
- IPSec VPN
- VLAN segmentation

### 4.3 Application & Data Security
- AES 256 encryption
- TLS 1.3
- Patch management
- RBAC access

### 4.4 IAM Policies
- MFA
- Zero Trust
- Strong password policy

### 4.5 Email & Endpoint Security
- EDR protection
- Email filtering

### 4.6 AI Security Monitoring
- Anomaly detection
- Threat scoring
- User behavior analytics
''',

    "5. Branch-to-Branch Data Security Plan": '''
### 5.1 Encrypted VPN Mesh
- IPSec encrypted tunnels

### 5.2 Secure File Transfer
- SFTP
- FTPS
- MFA cloud storage

### 5.3 Central SOC Log Monitoring
- Unified logs from all branches

### 5.4 Data Loss Prevention
- USB block
- Prevent cloud upload
- Prevent sensitive email sending

### 5.5 Backup Strategy
- Daily incremental backup
- Weekly full backup
- DR Site in Pune
''',

    "6. Incident Response & Recovery": '''
### Incident Response Team
- Analysts
- IT admins
- Forensic experts
- Network engineers

### Process
1. Detection
2. Containment
3. Eradication
4. Recovery
5. Documentation

### Business Continuity
Ensures services stay active during cyberattacks.
''',

    "7. Results After Implementation": '''
- 80% reduction in phishing
- 60% improvement in secure communication
- Zero major breaches
- Fast threat detection
- High employee compliance
''',

    "8. Conclusion": '''
TechNova successfully implemented a multi-layered cybersecurity system,
improving monitoring, communication security, and compliance.
'''
}   # <-- THIS closes the dictionary PROPERLY

# ---------------------- SEARCH HIGHLIGHT ----------------------
def highlight(text, query):
    if query.lower() in text.lower():
        return text.replace(query, f"**🟡 {query}**")
    return text

# ---------------------- MAIN LAYOUT ----------------------
col1, col2 = st.columns([1, 2])

# ---------------------- LEFT MENU ----------------------
with col1:
    st.subheader("📚 Subjects")

    selected = st.radio(
        "Select a topic:",
        list(content.keys())
    )

    st.success(f"📌 You selected: **{selected}**")

# ---------------------- RIGHT CONTENT ----------------------
with col2:
    st.subheader("📄 Content Viewer")

    if search_query:
        st.markdown(highlight(content[selected], search_query), unsafe_allow_html=True)
    else:
        st.markdown(content[selected], unsafe_allow_html=True)

# ---------------------- DOWNLOAD ----------------------
st.write("---")
st.subheader("⬇️ Download Full Case Study")

full_text = ""
for title, body in content.items():
    full_text += title + "\n" + body + "\n\n"

st.download_button(
    label="Download as TXT",
    data=full_text.encode(),
    file_name="TechNova_Case_Study.txt",
    mime="text/plain"
)
