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
**TechNova Solutions Pvt. Ltd.** is a mid-sized IT service provider in **Mumbai** with branches in  
**Bengaluru, Hyderabad, and Pune**.

Problems faced:
- Unauthorized access  
- Data leakage  
- Weak authentication  
- Unsecured inter-branch communication  

A **new security system + data protection strategy** was developed.
''',

    "2. Objectives of the Security Plan": '''
- **Protect company data & infrastructure**  
- **Block unauthorized access**  
- **Encrypt branch communications**  
- **AI-driven cyberattack monitoring**  
- **Compliance with ISO 27001 & GDPR**  
''',

    "3. Existing Security Challenges": '''
### **3.1 Network Vulnerabilities**
- Basic routers  
- No central monitoring  

### **3.2 Weak Access Controls**
- Password sharing  
- No MFA  
- Poor admin control  

### **3.3 Unsecured Data Transfer**
- Email-based file sharing  
- No VPN  

### **3.4 Incident Response Gaps**
- No SOC  
- No log analysis  
''',
