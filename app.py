import streamlit as st
from streamlit_extras.colored_header import colored_header
from streamlit_extras.card import card

st.set_page_config(
    page_title="Security System Plan",
    layout="wide",
    page_icon="🔐"
)

# ------------------------------------------
# CUSTOM PAGE STYLING
# ------------------------------------------
st.markdown("""
<style>
.big-title {
    font-size: 38px !important;
    color: #2B547E;
    font-weight: 900;
}
.section-title {
    font-size: 28px !important;
    color: #1F4E79;
    margin-top: 20px;
    font-weight: 800;
}
.info-box {
    background: #F0F8FF;
    padding: 18px;
    border-radius: 12px;
    border-left: 6px solid #2B547E;
    margin-bottom: 10px;
}
.metric-card {
    padding: 20px;
    background: #EBF5FB;
    border-radius: 12px;
    text-align: center;
    box-shadow: 0 0 8px rgba(0,0,0,0.15);
}
</style>
""", unsafe_allow_html=True)

st.markdown("<div class='big-title'>🔐 Company Security & Branch Data Protection System</div>", unsafe_allow_html=True)
st.write("A modern & interactive single-page security planning application.")

# ------------------------------------------
# SIDEBAR MENU
# ------------------------------------------
menu = st.sidebar.radio(
    "📌 Navigate",
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

# =====================================================
# 1. OBJECTIVES
# =====================================================
if menu == "Objectives":
    st.markdown("<div class='section-title'>🎯 Objectives of Security Plan</div>", unsafe_allow_html=True)

    colored_header("Primary Goals", description="", color_name="blue-70")

    st.markdown("""
    <div class='info-box'>
    ✔ Protect organizational assets (Digital + Physical)<br>
    ✔ Maintain CIA Triad — Confidentiality, Integrity, Availability<br>
    ✔ Prevent unauthorized access & data leakage<br>
    ✔ Strengthen branch-to-branch secure communication<br>
    ✔ Enable AI-powered real-time threat detection<br>
    ✔ Build structured incident response capability<br>
    ✔ Ensure compliance with standards (ISO 27001, GDPR, IT Act)
    </div>
    """, unsafe_allow_html=True)

# =====================================================
# 2. EXISTING SECURITY CHALLENGES
# =====================================================
elif menu == "Existing Security Challenges":

    st.markdown("<div class='section-title'>⚠ Existing Security Challenges</div>", unsafe_allow_html=True)

    cols = st.columns(2)
    challenges = [
        "Weak physical access control",
        "Outdated firewall configuration",
        "No encryption between branches",
        "No centralized monitoring",
        "Phishing, malware & email risks",
        "Weak password hygiene",
        "Lack of incident response plan",
        "Manual log analysis delays detection"
    ]

    for i, c in enumerate(challenges):
        with cols[i % 2]:
            card(title=f"⚠ {c}", text="")

# =====================================================
# 3. COMPANY-WIDE SECURITY SYSTEM
# =====================================================
elif menu == "Company-Wide Security System":

    st.markdown("<div class='section-title'>🏢 Company-Wide Security System</div>", unsafe_allow_html=True)

    with st.expander("🔐 Physical Security Measures", expanded=True):
        st.markdown("""
        - Biometric authentication  
        - CCTV with face recognition  
        - Smart ID badges  
        - Restricted server room access  
        - Motion & intrusion sensors  
        """)

    with st.expander("🌐 Network Security Measures", expanded=False):
        st.markdown("""
        - Next-Gen Firewalls (NGFW)  
        - IDS/IPS monitoring  
        - Zero Trust Framework  
        - DDoS protection  
        - Secure VPN for remote users  
        """)

    with st.expander("💾 Application & Data Security", expanded=False):
        st.markdown("""
        **Encryption**  
        - AES-256 for data-at-rest  
        - TLS 1.3 for data-in-transit  

        **Email Security**  
        - Anti-phishing gateway  
        - SPF + DKIM + DMARC  

        **Endpoint Security**  
        - EDR, Anti-malware, Anti-ransomware  

        **Application Security**  
        - Secure coding standards  
        - VAPT / Penetration Testing  
        """)

    with st.expander("🤖 AI-Powered Security Monitoring", expanded=False):
        st.markdown("""
        - Anomaly detection in real time  
        - AI-driven bot detection  
        - Automated threat scoring  
        - SOAR-driven alert response  
        - Behavioral analytics (UEBA)  
        """)

# =====================================================
# 4. BRANCH-TO-BRANCH PLAN
# =====================================================
elif menu == "Branch-to-Branch Data Security":
    st.markdown("<div class='section-title'>🏬 Branch-to-Branch Data Security Plan</div>", unsafe_allow_html=True)

    st.markdown("""
    <div class='info-box'>
    ✔ Encrypted site-to-site VPN tunnel<br>
    ✔ MPLS dedicated secure lines<br>
    ✔ Multi-layer encryption gateways<br>
    ✔ Central authentication server<br>
    ✔ Cloud backup with multi-factor encryption<br>
    ✔ Data integrity hashing (SHA-256)<br>
    </div>
    """, unsafe_allow_html=True)

# =====================================================
# 5. INCIDENT RESPONSE
# =====================================================
elif menu == "Incident Response & Recovery":

    st.markdown("<div class='section-title'>🚨 Incident Response & Recovery Plan</div>", unsafe_allow_html=True)

    steps = [
        "📘 Preparation — Tools, training, playbooks",
        "🔍 Identification — Detect threats via SIEM & AI",
        "🧯 Containment — Stop lateral movement",
        "🗑 Eradication — Remove malware & threats",
        "♻ Recovery — Restore systems & services",
        "📝 Lessons Learned — Update security posture"
    ]

    for s in steps:
        card(title=s)

    st.subheader("🔄 Disaster Recovery Objectives")
    st.markdown("""
    - Daily encrypted backups  
    - Hot-standby secondary servers  
    - Cloud DR site  
    - **RTO: 2 hours**  
    - **RPO: 15 minutes**  
    """)

# =====================================================
# 6. RESULTS AFTER IMPLEMENTATION
# =====================================================
elif menu == "Security Implementation Results":
    st.markdown("<div class='section-title'>📊 Security Impact After Implementation</div>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)

    col1.markdown("<div class='metric-card'><h2>70%↓</h2>Unauthorized Access</div>", unsafe_allow_html=True)
    col2.markdown("<div class='metric-card'><h2>85%↑</h2>Threat Detection Speed</div>", unsafe_allow_html=True)
    col3.markdown("<div class='metric-card'><h2>99.99%</h2>System Uptime</div>", unsafe_allow_html=True)

    st.markdown("""
    - Malware incidents reduced by **60%**  
    - Faster data transfer between branches  
    - Zero major cybersecurity breaches  
    """)

# =====================================================
# 7. INTERACTIVE CASE SIMULATION
# =====================================================
elif menu == "Interactive Case Simulator":

    st.markdown("<div class='section-title'>🧪 Interactive Cybersecurity Case Simulator</div>", unsafe_allow_html=True)

    case = st.selectbox(
        "Select a Case to Simulate",
        [
            "Phishing Attack Detection",
            "Network Intrusion Attempt",
            "Branch Data Transfer Failure",
            "Insider Threat Activity",
            "Malware Outbreak Response"
        ]
    )

    st.subheader(f"Selected Case: {case}")

    if case == "Phishing Attack Detection":
        email = st.text_area("Paste suspicious email content:")
        if st.button("Analyze"):
            st.error("⚠ High Risk Phishing Email Detected!")

    elif case == "Network Intrusion Attempt":
        val = st.slider("Abnormal Traffic Level (%)", 0, 200)
        if val > 130:
            st.error("🚨 Intrusion Detected by IDS!")
        else:
            st.success("Normal Traffic")

    elif case == "Branch Data Transfer Failure":
        branch = st.selectbox("Select Branch", ["Mumbai", "Pune", "Delhi"])
        if st.button("Diagnose"):
            st.warning(f"⚠ VPN Tunnel Failure in {branch} Branch")

    elif case == "Insider Threat Activity":
        emp = st.text_input("Employee ID:")
        if st.button("Scan Logs"):
            st.error(f"🔍 Unusual File Access Detected for {emp}")

    elif case == "Malware Outbreak Response":
        num = st.number_input("Infected Systems", 1, 300)
        if num > 40:
            st.error("🔥 Major Malware Outbreak — Isolation Required!")
        else:
            st.success("Minor infection — Isolated Successfully")
