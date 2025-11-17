import streamlit as st
from io import BytesIO

# ---------------------- APP CONFIG ----------------------
st.set_page_config(
    page_title="TechNova Security Case Study",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("<h1 style='text-align:center;'>📘 <b>TechNova Security Case Study</b></h1>", unsafe_allow_html=True)
st.write("---")

# ---------------------- SEARCH BAR ----------------------
search_query = st.sidebar.text_input("🔍 Search Inside Case Study")
st.sidebar.write("---")

# ---------------------- CASE STUDY CONTENT ----------------------
case_study = {
    "1. Introduction": """
**TechNova Solutions Pvt. Ltd.** is a mid-sized IT service provider with its head office in **Mumbai**
and branch offices in **Bengaluru, Hyderabad, and Pune**.

The company was facing cyber threats like:
- Unauthorized access
- Data leakage
- Weak authentication
- Unsecured inter-branch communication

TechNova created a **Company Security System Plan** and a **Branch-to-Branch Data Security Strategy**.
""",

    "2. Objectives of the Security Plan": """
The main objectives:

- **Safeguard company data & infrastructure**
- **Prevent unauthorized access**
- **Ensure encrypted communication between branches**
- **Deploy cyberattack dete**

