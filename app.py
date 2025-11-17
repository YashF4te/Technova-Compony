import streamlit as st

# ---------------------- PAGE CONFIG ----------------------
st.set_page_config(
    page_title="TechNova Cybersecurity Practical",
    layout="wide",
)

# ---------------------- CSS ANIMATION ----------------------
st.markdown("""
<style>

@keyframes fadeIn {
  0% {opacity: 0;}
  100% {opacity: 1;}
}

@keyframes slideIn {
  0% {transform: translateX(-20px); opacity: 0;}
  100% {transform: translateX(0); opacity: 1;}
}

@keyframes cardPop {
  0% {transform: scale(0.95); opacity: 0;}
  100% {transform: scale(1); opacity: 1;}
}

div.block-container {
    animation: fadeIn 1.2s ease-in-out;
}

.section-card {
    padding: 15px;
    background: #f8f9fa;
    border-radius: 12px;
    box-shadow: 0px 3px 10px rgba(0,0,0,0.1);
    margin-bottom: 18px;
    animation: cardPop 0.6s ease-out;
}

.section-card:hover {
    transform: scale(1.02);
    transition: 0.3s;
    background: #ffffff;
    box-shadow: 0px 6px 18px rgba(0,0,0,0.15);
}

.radio-animation label {
    animation: slideIn 0.5s ease-out;
}

.download-btn {
    animation: fadeIn 1.2s ease;
}

</style>
""", unsafe_allow_html=True)

# ---------------------- HEADER ----------------------
st.markdown("<h1 style='text-align:center; animation: fadeIn 1.5s;'>🧪 <b>TechNova Cybersecurity – Practical</b></h1>", unsafe_allow_html=True)
st.write("---")

# ---------------------- PRACTICAL CONTENT ----------------------
practical = {
    "1. Aim": '''
To implement a complete cybersecurity infrastructure including Network Security, Data Protection, 
IAM, SOC Monitoring, and Secure Branch-to-Branch Communication.
''',

    "2. Requirements": '''
### Hardware:
- NGFW Firewall
- Biometric Scanner
- CCTV Cameras
- RFID ID Cards
- Server Systems

### Software:
- MFA
- VPN (IPSec)
- IDS/IPS
- EDR
- Patch Management
- SOC Monitoring Tools
- DLP System
''',

    "3. Theory": '''
### Network Security
- NGFW, IDS/IPS, VPN Tunnels, VLANs

### Identity & Access
- MFA, Password Policy, Zero Trust

### Data Security
- AES-256, TLS 1.3, RBAC

### Endpoint & Email
- EDR, Anti-phishing, Secure Gateway

### AI Monitoring
- Anomaly Detection, UBA, Auto Alerts
''',

    "4. Procedure": '''
### Step 1 — Physical Security
- Install Biometrics, CCTV, RFID

### Step 2 — Network Security
- Configure NGFW, IDS/IPS, VPN, VLANs

### Step 3 — Access Control
- Enable MFA, Set Password Policies

### Step 4 — Data Security
- Use AES-256, TLS 1.3, RBAC

### Step 5 — Endpoint Security
- Install EDR, Enable Email Filtering

### Step 6 — SOC Monitoring
- Enable AI Alerts & Log Analysis

### Step 7 — Branch Security
- VPN Mesh, SFTP, Central SOC Logs

### Step 8 — Backup
- Daily Incremental, Weekly Full, DR Site
''',

    "5. Output / Result": '''
- 80% phishing reduction  
- 60% better communication security  
- Zero major breaches  
- Faster detection  
- Better employee awareness  
''',

    "6. Conclusion": '''
TechNova now has a strong, layered cybersecurity infrastructure with AI monitoring, 
secure communication, and complete protection.
'''
}

# ---------------------- SEARCH BAR ----------------------
search_query = st.sidebar.text_input("🔍 Search Practical Content")

# ---------------------- SIDEBAR MENU ----------------------
st.sidebar.subheader("📚 Practical Sections")

selected = st.sidebar.radio(
    "Select a Section:",
    list(practical.keys()),
    key="menu",
)

# ---------------------- MAIN CONTENT WITH ANIMATION ----------------------
st.markdown(f"<div class='section-card'><h2>{selected}</h2></div>", unsafe_allow_html=True)

content_to_show = practical[selected]

# Highlight if searched
if search_query:
    content_to_show = content_to_show.replace(
        search_query, f"**🟡 {search_query}**"
    )

st.markdown(
    f"<div class='section-card'>{content_to_show}</div>",
    unsafe_allow_html=True
)

# ---------------------- DOWNLOAD BUTTON ----------------------
st.write("---")
st.subheader("⬇️ Download Practical File")

full_text = ""
for title, body in practical.items():
    full_text += title + "\n" + body + "\n\n"

st.download_button(
    label="Download as TXT",
    data=full_text.encode(),
    file_name="TechNova_Practical.txt",
    mime="text/plain",
    key="download",
)
