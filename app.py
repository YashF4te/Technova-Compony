import streamlit as st

# ---------------------- PAGE CONFIG ----------------------
st.set_page_config(
    page_title="TechNova Cybersecurity Practical",
    layout="wide",
)

st.markdown("<h1 style='text-align:center;'>🧪 <b>TechNova Cybersecurity Practical</b></h1>", unsafe_allow_html=True)
st.write("---")

# ---------------------- SIDEBAR SEARCH ----------------------
search_query = st.sidebar.text_input("🔍 Search Practical Content")
st.sidebar.write("---")

# ---------------------- PRACTICAL FORMAT CONTENT ----------------------
practical = {
    "1. Aim": '''
To design and implement a complete cybersecurity infrastructure for TechNova Solutions, 
covering Network Security, Identity & Access Management, Data Security, Incident Response, 
and Secure Inter-Branch Communication.
''',

    "2. Requirements": '''
### Hardware Requirements:
- Firewall appliance (NGFW)
- Biometric scanners
- AI-enabled CCTV cameras
- RFID access cards
- Server systems

### Software Requirements:
- VPN (IPSec)
- IDS/IPS Security Tools
- Multi-Factor Authentication (MFA)
- Endpoint Detection & Response (EDR)
- Patch Management Tool
- Security Operations Center (SOC)
- Data Loss Prevention (DLP)
''',

    "3. Theory": '''
### 3.1 Network Security
- NGFW installed in each branch
- IDS/IPS enabled for threat detection
- IPSec VPN tunnels between branches
- VLAN segmentation (Admin, HR, IT, Guest)

### 3.2 Identity & Access Management (IAM)
- MFA enabled for all users
- Strong password policies
- Zero Trust Authentication

### 3.3 Data Security
- AES-256 encryption for stored data
- TLS 1.3 for in-transit data
- Role-Based Access Control (RBAC)

### 3.4 Endpoint & Email Security
- EDR installed on all systems
- Anti-phishing, anti-spoofing email gateway

### 3.5 AI-Based Monitoring
- Real-time anomaly detection
- User Behavior Analytics (UBA)
- Automated alerts
''',

    "4. Procedure": '''
### Step 1: Physical Security Setup
1. Install biometric scanners at server rooms.
2. Deploy AI CCTV cameras.
3. Issue RFID smart access cards.

### Step 2: Network Security Setup
1. Install NGFW in each branch office.
2. Configure IDS & IPS rules.
3. Create IPSec VPN mesh network.
4. Configure VLANs for segmentation.

### Step 3: Identity & Access Control Setup
1. Enable MFA for all employee accounts.
2. Apply password policy (12 chars + 45-day change).
3. Implement Zero Trust authentication.

### Step 4: Data Security Implementation
1. Apply AES-256 encryption.
2. Enable TLS 1.3 for all communication.
3. Enforce RBAC for database access.

### Step 5: Endpoint & Email Security Setup
1. Install EDR on all employee devices.
2. Enable secure email gateway protections.

### Step 6: AI-Based SOC Monitoring
1. Enable anomaly detection.
2. Configure threat scoring.
3. Enable automatic alerting.

### Step 7: Branch-to-Branch Security
1. Set up VPN mesh network.
2. Implement Secure File Transfer (SFTP/FTPS).
3. Enable central SOC log monitoring.
4. Enforce DLP policies.

### Step 8: Backup & Recovery
1. Daily incremental backups.
2. Weekly full backups.
3. Disaster recovery replica in Pune.
''',

    "5. Output / Result": '''
- 80% reduction in phishing attacks
- 60% more secure communication
- Zero major cyber breaches
- Faster threat detection
- Improved employee compliance
''',

    "6. Conclusion": '''
TechNova successfully implemented a practical multilayer cybersecurity system that 
improved overall protection, secure communication, AI monitoring, and industry compliance.
'''
}

# ---------------------- SEARCH HIGHLIGHT FUNCTION ----------------------
def highlight(text, query):
    if query.lower() in text.lower():
        return text.replace(query, f"**🟡 {query}**")
    return text

# ---------------------- LAYOUT ----------------------
col1, col2 = st.columns([1, 2])

# ---------------------- LEFT SIDE MENU ----------------------
with col1:
    st.subheader("📚 Practical Sections")

    selected = st.radio(
        "Select a section:",
        list(practical.keys())
    )

    st.success(f"📌 Selected Section: **{selected}**")

# ---------------------- RIGHT SIDE CONTENT ----------------------
with col2:
    st.subheader("📄 Practical Content Viewer")

    if search_query:
        st.markdown(highlight(practical[selected], search_query), unsafe_allow_html=True)
    else:
        st.markdown(practical[selected], unsafe_allow_html=True)

# ---------------------- DOWNLOAD SECTION ----------------------
st.write("---")
st.subheader("⬇️ Download Full Practical File")

full_practical_text = ""
for title, body in practical.items():
    full_practical_text += title + "\n" + body + "\n\n"

st.download_button(
    label="Download Practical as TXT",
    data=full_practical_text.encode(),
    file_name="TechNova_Practical.txt",
    mime="text/plain"
)
