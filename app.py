import streamlit as st

st.set_page_config(
    page_title="TechNova Security System",
    layout="wide",
    page_icon="🔐"
)

# ------------------------------------------------------------
# Beautiful Custom CSS (No external packages required)
# ------------------------------------------------------------
st.markdown("""
<style>

body {
    background-color: #F7F9FC !important;
}

.big-title {
    font-size: 40px !important;
    font-weight: 900;
    color: #1F4E79;
    text-align: center;
    margin-bottom: 20px;
}

.section-box {
    background: white;
    padding: 22px;
    border-radius: 14px;
    box-shadow: 0 0 10px rgba(0,0,0,0.1);
    margin-bottom: 25px;
    border-left: 6px solid #1F4E79;
}

.sub-title {
    font-size: 26px;
    font-weight: 800;
    color: #1F4E79;
    margin-bottom: 12px;
}

.metric-card {
    background:#EAF2F8;
    padding:25px;
    border-radius:12px;
    box-shadow:0 0 10px rgba(0,0,0,0.1);
    text-align:center;
}

</style>
""", unsafe_allow_html=True)

# ------------------------------------------------------------
# HEADER
# ------------------------------------------------------------
st.markdown("<div class='big-title'>🔐 TechNova Cybersecurity & Branch Protection System</div>", unsafe_allow_html=True)

# ------------------------------------------------------------
# SIDEBAR
# ------------------------------------------------------------
menu = st.sidebar.radio(
    "📌 Navigation",
    [
        "Objectives",
        "Existing Security Challenges",
        "Company-Wide Security System",
        "Branch-to-Branch Data Security",
        "Incident Response & Recovery",
        "Security Implementation Results",
        "Interactive Case Simulator"
    ]
)

# ------------------------------------------------------------
# OBJECTIVES
# ------------------------------------------------------------
if menu == "Objectives":

    st.markdown("<div class='sub-title'>🎯 Security Plan Objectives</div>", unsafe_allow_html=True)

    st.markdown("""
    <div class='section-box'>
    ✔ Protect all digital & physical assets<br>
    ✔ Enforce CIA Triad (Confidentiality, Integrity, Availability)<br>
    ✔ Prevent unauthorized access & internal misuse<br>
    ✔ Build AI-powered real-time threat detection<br>
    ✔ Strengthen branch-to-branch secure communication<br>
    ✔ Implement enterprise-wide encryption<br>
    ✔ Improve compliance (ISO, GDPR, IT Act)<br>
    </div>
    """, unsafe_allow_html=True)

# ------------------------------------------------------------
# EXISTING SECURITY CHALLENGES
# ------------------------------------------------------------
elif menu == "Existing Security Challenges":

    st.markdown("<div class='sub-title'>⚠ Existing Security Weaknesses</div>", unsafe_allow_html=True)

    challenges = [
        "Weak physical access control",
        "Unsecured Wi-Fi networks",
        "Firewall not updated",
        "Branch-to-branch traffic unencrypted",
        "Manual log analysis",
        "High phishing risk",
        "No AI-based monitoring",
        "Weak endpoint protection"
    ]

    cols = st.columns(2)
    for i, c in enumerate(challenges):
        with cols[i % 2]:
            st.markdown(f"""
            <div class='section-box'>
            ⚠ {c}
            </div>
            """, unsafe_allow_html=True)

# ------------------------------------------------------------
# COMPANY-WIDE SECURITY SYSTEM
# ------------------------------------------------------------
elif menu == "Company-Wide Security System":

    st.markdown("<div class='sub-title'>🏢 Company-Wide Security Framework</div>", unsafe_allow_html=True)

    with st.expander("🔐 Physical Security Measures", expanded=True):
        st.write("""
        - Biometric entry  
        - CCTV + motion detection  
        - Smart ID access zones  
        - Restricted server room  
        """)

    with st.expander("🌐 Network Security Measures"):
        st.write("""
        - NGFW (Next-Gen Firewall)  
        - IDS/IPS  
        - Zero Trust network model  
        - Secure VPN  
        - DDoS Protection  
        """)

    with st.expander("💾 Application & Data Security"):
        st.write("""
        **Encryption**
        - AES-256 data-at-rest  
        - TLS 1.3 data-in-transit  

        **Endpoint Security**
        - Anti-ransomware  
        - EDR monitoring  

        **Email Protection**
        - SPF + DKIM + DMARC  
        - Anti-phishing filters  
        """)

    with st.expander("🤖 AI-Powered Security Monitoring"):
        st.write("""
        - AI anomaly detection  
        - Behavioral analytics  
        - Automated threat scoring  
        - Real-time SIEM alerts  
        """)

# ------------------------------------------------------------
# BRANCH TO BRANCH SECURITY
# ------------------------------------------------------------
elif menu == "Branch-to-Branch Data Security":

    st.markdown("<div class='sub-title'>🏬 Branch-to-Branch Encryption & Protection</div>", unsafe_allow_html=True)

    st.markdown("""
    <div class='section-box'>
    ✔ Encrypted VPN tunnels<br>
    ✔ Dedicated MPLS circuits<br>
    ✔ Central authentication server<br>
    ✔ SHA-256 data integrity verification<br>
    ✔ Daily encrypted backups<br>
    ✔ Multi-layer encryption gateways<br>
    </div>
    """, unsafe_allow_html=True)

# ------------------------------------------------------------
# INCIDENT RESPONSE PLAN
# ------------------------------------------------------------
elif menu == "Incident Response & Recovery":

    st.markdown("<div class='sub-title'>🚨 Incident Response & Recovery Framework</div>", unsafe_allow_html=True)

    steps = [
        "📘 Preparation — Tools, training, playbooks",
        "🔍 Identification — Threat detection via AI + SIEM",
        "🧯 Containment — Stop lateral movement",
        "🗑 Eradication — Remove threat",
        "♻ Recovery — Restore operations",
        "📝 Lessons Learned — Improve future protection"
    ]

    for s in steps:
        st.markdown(f"<div class='section-box'>{s}</div>", unsafe_allow_html=True)

# ------------------------------------------------------------
# SECURITY RESULTS
# ------------------------------------------------------------
elif menu == "Security Implementation Results":
    st.markdown("<div class='sub-title'>📊 Security Improvements After Deployment</div>", unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3)

    c1.markdown("<div class='metric-card'><h2>70%↓</h2>Unauthorized Access Attempts</div>", unsafe_allow_html=True)
    c2.markdown("<div class='metric-card'><h2>85%↑</h2>Threat Detection Speed</div>", unsafe_allow_html=True)
    c3.markdown("<div class='metric-card'><h2>99.99%</h2>System Uptime</div>", unsafe_allow_html=True)

# ------------------------------------------------------------
# INTERACTIVE CASE SIMULATOR
# ------------------------------------------------------------
elif menu == "Interactive Case Simulator":

    st.markdown("<div class='sub-title'>🧪 Cybersecurity Case Simulator</div>", unsafe_allow_html=True)

    case = st.selectbox(
        "Choose Simulation Case",
        [
            "Phishing Attack Detection",
            "Network Intrusion Attempt",
            "Branch Data Failure",
            "Insider Threat",
            "Malware Outbreak"
        ]
    )

    st.write("---")

    if case == "Phishing Attack Detection":
        email = st.text_area("Paste suspicious email:")
        if st.button("Analyze Email"):
            st.error("⚠ High-Risk Phishing Pattern Detected!")

    elif case == "Network Intrusion Attempt":
        traffic = st.slider("Abnormal Traffic (%)", 0, 200)
        if traffic > 130:
            st.error("🚨 Intrusion Detected!")
        else:
            st.success("No abnormal activity.")

    elif case == "Branch Data Failure":
        branch = st.selectbox("Select branch", ["Mumbai", "Pune", "Delhi"])
        if st.button("Diagnose"):
            st.warning(f"⚠ VPN tunnel down for {branch}!")

    elif case == "Insider Threat":
        emp = st.text_input("Enter Employee ID:")
        if st.button("Scan Logs"):
            st.error(f"🔍 Insider anomaly detected for employee {emp}")

    elif case == "Malware Outbreak":
        count = st.number_input("Infected systems:", 1, 300)
        if count > 40:
            st.error("🔥 Severe outbreak detected — isolate network!")
        else:
            st.success("Contained successfully.")
