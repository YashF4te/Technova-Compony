import streamlit as st

st.set_page_config(page_title="Security System Plan", layout="wide")

st.title("🔐 Company Security System & Branch-to-Branch Data Security Plan")

# Sidebar Navigation
menu = st.sidebar.selectbox(
    "Navigate",
    [
        "Objectives of Security Plan",
        "Existing Security Challenges",
        "Company-Wide Security System",
        "Branch-to-Branch Data Security Plan",
        "Incident Response & Recovery Plan",
        "Result After Implementation",
        "Interactive Case Simulation"
    ]
)

# ------------------------------------
# 1. Objectives
# ------------------------------------
if menu == "Objectives of Security Plan":
    st.header("🎯 Objectives of Security Plan")

    st.write("""
    - Protect organizational assets from cyber & physical threats  
    - Ensure confidentiality, integrity, and availability (CIA triad)  
    - Prevent unauthorized access and data breaches  
    - Secure communication between branches  
    - Detect threats in real time using AI-powered monitoring  
    - Build incident response capability  
    - Maintain regulatory compliance (ISO 27001, GDPR, IT Act)  
    """)

# ------------------------------------
# 2. Existing Challenges
# ------------------------------------
elif menu == "Existing Security Challenges":
    st.header("⚠️ Existing Security Challenges")

    st.write("""
    - Weak physical access controls  
    - Outdated network firewall setup  
    - Lack of encryption for branch communication  
    - Manual monitoring increases risk of delayed detection  
    - High chance of phishing, malware and email attacks  
    - No central incident management process  
    - Poor password hygiene among employees  
    """)

# ------------------------------------
# 3. Company-Wide Security System
# ------------------------------------
elif menu == "Company-Wide Security System":

    st.header("🏢 Company-Wide Security System Plan")

    st.subheader("1️⃣ Physical Security Measures")
    st.write("""
    - Biometric access control  
    - CCTV cameras with face recognition  
    - Smart ID cards  
    - Server room restricted access  
    - Motion detection sensors  
    """)

    st.subheader("2️⃣ Network Security Measures")
    st.write("""
    - Next-Gen Firewall (NGFW)  
    - Intrusion Detection & Prevention System (IDS/IPS)  
    - VPN for remote employees  
    - Network segmentation  
    - Zero Trust Network Access (ZTNA)  
    """)

    st.subheader("3️⃣ Application & Data Security")
    st.write("""
    **Encryption:**  
    - AES-256 encryption for data at rest  
    - TLS 1.3 encryption for data in transit  

    **Email Security:**  
    - Anti-phishing filters  
    - SPF, DKIM & DMARC authentication  

    **Endpoint Security:**  
    - EDR (Endpoint Detection & Response)  
    - Anti-malware & ransomware protection  

    **Application Security:**  
    - Secure SDLC  
    - Penetration testing  
    - API security (OAuth2, JWT)  
    """)

    st.subheader("4️⃣ AI-Powered Security Monitoring")
    st.write("""
    - Real-time anomaly detection  
    - Automated threat scoring  
    - Bot detection system  
    - AI-based network behavior analysis  
    - Alert automation using SOAR  
    """)

# ------------------------------------
# 4. Branch-to-Branch Security
# ------------------------------------
elif menu == "Branch-to-Branch Data Security Plan":

    st.header("🏬 Branch-to-Branch Data Security Plan")

    st.write("""
    ✔️ Encrypted site-to-site VPN  
    ✔️ MPLS secure connection  
    ✔️ Dedicated encryption gateway  
    ✔️ Centralized authentication server  
    ✔️ Cloud-based backup with multi-factor encryption  
    ✔️ Data integrity verification (SHA-256 hashing)  
    """)

# ------------------------------------
# 5. Incident Response
# ------------------------------------
elif menu == "Incident Response & Recovery Plan":

    st.header("🚨 Incident Response & Recovery Plan")

    st.write("""
    ### 🧭 Incident Response Lifecycle (NIST Model)
    1. **Preparation:** Security tools, training, playbooks  
    2. **Identification:** Detect the attack (AI alerts, SIEM logs)  
    3. **Containment:** Stop the spread of the attack  
    4. **Eradication:** Remove malware / unauthorized access  
    5. **Recovery:** Restore systems & data  
    6. **Lessons Learned:** Improve security posture  

    ### 🔄 Disaster Recovery
    - Daily encrypted backups  
    - Hot standby servers  
    - Cloud DR site  
    - RTO: 2 hours | RPO: 15 minutes  
    """)

# ------------------------------------
# 6. Results After Implementation
# ------------------------------------
elif menu == "Result After Implementation":
    st.header("📊 Result After Implementation")

    st.write("""
    - 70% reduction in unauthorized access  
    - 85% improvement in threat detection  
    - 60% reduction in malware/phishing incidents  
    - 99.99% uptime with improved disaster recovery  
    - Fast branch-to-branch data flow  
    - Zero major security breaches reported  
    """)

# ------------------------------------
# 7. Interactive Case Simulation
# ------------------------------------
elif menu == "Interactive Case Simulation":

    st.header("🧪 Interactive Case Simulation")

    case = st.selectbox(
        "Choose a Case to Simulate",
        [
            "Phishing Attack Simulation",
            "Network Intrusion Detection",
            "Branch Data Transfer Failure",
            "Insider Threat Activity",
            "Malware Outbreak"
        ]
    )

    st.subheader(f"📝 Case Selected: {case}")

    if case == "Phishing Attack Simulation":
        user_email = st.text_input("Enter suspicious email text:")
        if st.button("Analyze Email"):
            st.success("AI Detected: High probability of phishing! 🚨")

    elif case == "Network Intrusion Detection":
        traffic = st.slider("Abnormal Traffic Level (%)", 0, 200)
        if traffic > 120:
            st.error("Possible Intrusion Detected! IDS Triggered 🚨")
        else:
            st.info("Network traffic is normal.")

    elif case == "Branch Data Transfer Failure":
        branch = st.selectbox("Select Branch", ["Mumbai", "Pune", "Delhi"])
        if st.button("Run Diagnostic"):
            st.warning(f"{branch} Branch: VPN Tunnel Failure Detected!")

    elif case == "Insider Threat Activity":
        user = st.text_input("Enter Employee ID:")
        if st.button("Check Logs"):
            st.error(f"Unusual file access detected for user {user}!")

    elif case == "Malware Outbreak":
        infected = st.number_input("Number of infected systems", 1, 500)
        if infected > 50:
            st.error("Severe Malware Outbreak! Activate Response Team")
        else:
            st.success("Low-level malware detected and isolated.")

