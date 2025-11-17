import streamlit as st

st.set_page_config(
    page_title="TechNova Cybersecurity System",
    layout="wide",
    page_icon="🔐"
)

# -------------------------------------------------------------------
# GLOBAL THEME (Streamlit Cloud compatible)
# -------------------------------------------------------------------

st.markdown("""
<style>
/* Main Title */
.big-title {
    font-size: 42px;
    font-weight: 900;
    text-align: center;
    color: #1a3c66;
    margin-bottom: 15px;
}

/* Section Container */
.section {
    background: white;
    padding: 25px;
    border-radius: 14px;
    margin-bottom: 25px;
    border: 1px solid #d9e2ef;
    box-shadow: 0 3px 10px rgba(0,0,0,0.09);
}

/* Section Title */
.section-title {
    font-size: 28px;
    font-weight: 800;
    color: #1a3c66;
    margin-bottom: 10px;
}

/* Bullet points */
.section ul {
    font-size: 18px;
    line-height: 1.6;
}

/* Nice cards */
.card {
    background: #eef5ff;
    padding: 18px;
    border-radius: 10px;
    margin-bottom: 12px;
    border-left: 5px solid #1a3c66;
}

/* Metrics */
.metric-box {
    background: #ebf3ff;
    padding: 25px;
    border-radius: 14px;
    text-align: center;
    font-weight: bold;
    font-size: 22px;
    box-shadow: 0 3px 12px rgba(0,0,0,0.1);
}
</style>
""", unsafe_allow_html=True)

# -------------------------------------------------------------------
# HEADER
# -------------------------------------------------------------------
st.markdown("<div class='big-title'>🔐 TechNova Cybersecurity & Branch Protection System</div>", unsafe_allow_html=True)

# -------------------------------------------------------------------
# SIDEBAR NAVIGATION
# -------------------------------------------------------------------
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

# -------------------------------------------------------------------
# 1. Objectives
# -------------------------------------------------------------------
if menu == "Objectives":
    st.markdown("<div class='section'>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>🎯 Security Plan Objectives</div>", unsafe_allow_html=True)

    st.markdown("""
    <ul>
        <li>Protect physical & digital company assets</li>
        <li>Implement CIA Triad (Confidentiality, Integrity, Availability)</li>
        <li>Prevent malware, phishing & internal threats</li>
        <li>Automate threat monitoring using AI</li>
        <li>Strengthen branch-to-branch data encryption</li>
        <li>Ensure compliance (ISO 27001, GDPR, IT Act)</li>
        <li>Establish fast & structured incident response</li>
    </ul>
    """, unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

# -------------------------------------------------------------------
# 2. Existing Security Challenges
# -------------------------------------------------------------------
elif menu == "Existing Security Challenges":
    st.markdown("<div class='section'>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>⚠ Existing Security Weaknesses</div>", unsafe_allow_html=True)

    challenges = [
        "Weak physical access control",
        "Unsecured Wi-Fi & guest network",
        "Firewall outdated or misconfigured",
        "Branch traffic not encrypted",
        "Manual log review (slow detection)",
        "High email phishing risk",
        "No automated threat intelligence",
        "Weak endpoint protection on PCs"
    ]

    for c in challenges:
        st.markdown(f"<div class='card'>• {c}</div>", unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

# -------------------------------------------------------------------
# 3. Company-Wide Security System
# -------------------------------------------------------------------
elif menu == "Company-Wide Security System":

    # Physical Security
    st.markdown("<div class='section'>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>🔐 Physical Security Measures</div>", unsafe_allow_html=True)
    st.markdown("""
    <ul>
        <li>Biometric entry control</li>
        <li>CCTV surveillance with motion detection</li>
        <li>Restricted server room access</li>
        <li>Smart ID badges</li>
        <li>Fire & intrusion detection sensors</li>
    </ul>
    """, unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    # Network Security
    st.markdown("<div class='section'>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>🌐 Network Security Measures</div>", unsafe_allow_html=True)
    st.markdown("""
    <ul>
        <li>Next-Gen Firewall (NGFW)</li>
        <li>IDS/IPS threat detection</li>
        <li>Zero Trust access architecture</li>
        <li>Secure VPN (IPSec/TLS)</li>
        <li>DDoS protection</li>
    </ul>
    """, unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    # Application & Data Security
    st.markdown("<div class='section'>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>💾 Application & Data Security</div>", unsafe_allow_html=True)
    st.markdown("""
    <ul>
        <li>AES-256 data encryption</li>
        <li>TLS 1.3 secure communication</li>
        <li>Email security (SPF, DKIM, DMARC)</li>
        <li>EDR-based endpoint protection</li>
        <li>Regular VAPT testing</li>
    </ul>
    """, unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    # AI Security
    st.markdown("<div class='section'>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>🤖 AI-Powered Security Monitoring</div>", unsafe_allow_html=True)
    st.markdown("""
    <ul>
        <li>AI threat anomaly detection</li>
        <li>Behavior analytics (UEBA)</li>
        <li>Automated threat scoring</li>
        <li>Machine learning for suspicious activity</li>
        <li>Real-time SIEM alerts</li>
    </ul>
    """, unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

# -------------------------------------------------------------------
# 4. Branch-to-Branch Data Security
# -------------------------------------------------------------------
elif menu == "Branch-to-Branch Data Security":

    st.markdown("<div class='section'>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>🏬 Secure Branch-to-Branch Data Flow</div>", unsafe_allow_html=True)

    st.markdown("""
    <ul>
        <li>Encrypted site-to-site VPN</li>
        <li>MPLS secure private network</li>
        <li>Central authentication server</li>
        <li>SHA-256 integrity hashing</li>
        <li>Daily encrypted backups</li>
        <li>Multi-layer encryption gateways</li>
    </ul>
    """, unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

# -------------------------------------------------------------------
# 5. Incident Response Plan
# -------------------------------------------------------------------
elif menu == "Incident Response & Recovery":
    st.markdown("<div class='section'>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>🚨 Incident Response & Recovery Plan</div>", unsafe_allow_html=True)

    steps = [
        "📘 Preparation — Playbooks, tools, training",
        "🔍 Identification — Detect using AI + SIEM",
        "🧯 Containment — Block lateral movement",
        "🗑 Eradication — Remove malware/attack",
        "♻ Recovery — Restore systems securely",
        "📝 Lessons Learned — Update strategy"
    ]

    for s in steps:
        st.markdown(f"<div class='card'>{s}</div>", unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

# -------------------------------------------------------------------
# 6. Security Implementation Results
# -------------------------------------------------------------------
elif menu == "Security Implementation Results":

    st.markdown("<div class='section'>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>📊 Measured Security Improvements</div>", unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3)

    c1.markdown("<div class='metric-box'>70%↓ Unauthorized Access Attempts</div>", unsafe_allow_html=True)
    c2.markdown("<div class='metric-box'>85%↑ Threat Detection Speed</div>", unsafe_allow_html=True)
    c3.markdown("<div class='metric-box'>99.99% System Uptime</div>", unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

# -------------------------------------------------------------------
# 7. Interactive Case Simulator
# -------------------------------------------------------------------
elif menu == "Interactive Case Simulator":

    st.markdown("<div class='section'>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>🧪 Real-Time Security Case Simulator</div>", unsafe_allow_html=True)

    case = st.selectbox("Choose a simulation case", [
        "Phishing Email Detection",
        "Network Intrusion Attempt",
        "Branch Data Transfer Failure",
        "Insider Threat Activity",
        "Malware Outbreak Response"
    ])

    st.write(" ")

    if case == "Phishing Email Detection":
        email = st.text_area("Paste suspicious email content:")
        if st.button("Analyze Email"):
            st.error("⚠ Possible Phishing Detected!")

    elif case == "Network Intrusion Attempt":
        level = st.slider("Unusual Traffic Level (%)", 0, 200)
        if level > 130:
            st.error("🚨 Intrusion Alert!")
        else:
            st.success("Traffic Normal")

    elif case == "Branch Data Transfer Failure":
        branch = st.selectbox("Choose branch", ["Mumbai", "Pune", "Delhi"])
        if st.button("Diagnose Now"):
            st.warning(f"⚠ VPN Down for {branch}")

    elif case == "Insider Threat Activity":
        emp = st.text_input("Enter Employee ID:")
        if st.button("Scan Logs"):
            st.error(f"🔍 Suspicious Activity Detected for {emp}")

    elif case == "Malware Outbreak Response":
        count = st.number_input("Number of infected systems:", 1, 300)
        if count > 40:
            st.error("🔥 Critical Malware Outbreak — Isolation Required")
        else:
            st.success("Minor Infection — Resolved")

    st.markdown("</div>", unsafe_allow_html=True)
