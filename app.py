import streamlit as st
from io import BytesIO
from fpdf import FPDF

# ---------------------- APP CONFIG ----------------------
st.set_page_config(page_title="TechNova Security Case Study",
                   layout="wide",
                   initial_sidebar_state="expanded")

st.markdown("<h1 style='text-align:center;'>📘 <b>TechNova Security Case Study</b></h1>", unsafe_allow_html=True)
st.write("---")

# ---------------------- SEARCH BAR ----------------------
search_query = st.sidebar.text_input("🔍 Search Inside Case Study")
st.sidebar.write("---")

# ---------------------- CASE STUDY DATA ----------------------
case_study = {
    "1. Introduction": """
**TechNova Solutions Pvt. Ltd.** is a mid-sized IT service provider with its head office in **Mumbai** 
and branch offices in **Bengaluru, Hyderabad, and Pune**.

The company was facing cyber threats like:
- Unauthorized access  
- Data leakage  
- Weak authentication  
- Unsecured inter-branch communication  

To solve these issues, TechNova created a **Company Security System Plan** and a **Branch-to-Branch Data Security Strategy**.
""",

    "2. Objectives of the Security Plan": """
The main objectives:

- **Safeguard company data & infrastructure**
- **Prevent unauthorized access**
- **Ensure encrypted communication between branches**
- **Deploy cyberattack detection & response**
- **AI-driven monitoring & analytics**
- **Achieve ISO 27001 & GDPR compliance**
""",

    "3. Existing Security Challenges": """
### **3.1 Network Vulnerabilities**
- No enterprise firewalls  
- No centralized monitoring  

### **3.2 Weak Access Controls**
- Password sharing  
- No MFA  
- Poor admin privilege management  

### **3.3 Unsecured Branch Data Transfer**
- Data shared via email without encryption  
- No VPN tunnels  

### **3.4 Incident Response Gaps**
- No SOC  
- No log analysis  
""",

    "4. Company-Wide Security System Plan": """
TechNova adopted **Defense in Depth** and **Zero Trust Security Model**.

### **4.1 Physical Security**
- Biometric access  
- AI-powered CCTV  
- RFID cards  
- Fire suppression  

### **4.2 Network Security**
- **Next-Generation Firewalls**
- **IDS & IPS**
- **Encrypted IPSec VPN**
- **VLAN-based segmentation**

### **4.3 Application & Data Security**
- AES-256 encryption  
- TLS 1.3  
- Patch management  
- RBAC  
- Limited admin access  

### **4.4 Identity & Access Management**
- **MFA for all employees**
- **Zero Trust Login**
- Strong password policy  

### **4.5 Email & Endpoint Security**
- EDR protection  
- Secure email gateway (anti-phishing, anti-spoofing)

### **4.6 AI-Powered Security Monitoring**
- Real-time anomaly detection  
- Threat scoring  
- UBA (User Behavior Analytics)
""",

    "5. Branch-to-Branch Data Security Plan": """
### **5.1 Encrypted VPN Mesh**
- IPSec tunnels  
- Encrypted connectivity  

### **5.2 Secure File Transfer System (SFTS)**
- SFTP / FTPS  
- Encrypted cloud with MFA  

### **5.3 Central Log Monitoring**
- Logs from all branches sent to **central SOC**

### **5.4 Data Loss Prevention**
Blocks:
- USB data theft  
- External uploads  
- Sensitive email leaks  

### **5.5 Backup Strategy**
- Daily incremental  
- Weekly full  
- DR site: **Pune**  
""",

    "6. Incident Response & Recovery": """
### **6.1 Incident Response Team**
Includes analysts, IT admins, forensics, network experts.

### **6.2 Response Procedure**
1. Detection  
2. Containment  
3. Eradication  
4. Recovery  
5. Documentation  

### **6.3 Business Continuity**
Ensures critical services run during incidents.
""",

    "7. Results After Implementation": """
- **80% reduction** in phishing  
- **60% improvement** in secure communication  
- **Zero major breaches**  
- Faster detection  
- Higher employee compliance  
""",

    "8. Conclusion": """
TechNova successfully implemented a **multi-layered cybersecurity architecture**, improving infrastructure,
communication security, monitoring, and compliance.

This showcases how strong planning protects companies from modern cyber threats.
"""
}

# ---------------------- SEARCH FILTER ----------------------
def search_text(text, query):
    if query.lower() in text.lower():
        highlighted = text.replace(query, f"**🟡 {query}**")
        return highlighted
    return text

# ---------------------- CONTENT DISPLAY ----------------------
for section, content in case_study.items():
    with st.expander(f"📌 {section}", expanded=False):
        if search_query:
            st.markdown(search_text(content, search_query), unsafe_allow_html=True)
        else:
            st.markdown(content, unsafe_allow_html=True)

# ---------------------- PDF DOWNLOAD ----------------------
def generate_pdf():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Arial", size=12)

    for section, content in case_study.items():
        pdf.set_font("Arial", "B", 14)
        pdf.multi_cell(0, 10, section)
        pdf.ln(2)
        pdf.set_font("Arial", size=11)
        for line in content.split("\n"):
            pdf.multi_cell(0, 7, line)
        pdf.ln(5)

    pdf_bytes = pdf.output(dest="S").encode("latin1")
    return pdf_bytes

st.write("---")
st.subheader("📄 Download Case Study")

pdf_file = generate_pdf()
st.download_button(
    label="⬇️ Download PDF",
    data=pdf_file,
    file_name="TechNova_Case_Study.pdf",
    mime="application/pdf"
)
