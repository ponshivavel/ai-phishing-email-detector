import streamlit as st
import pickle
import re
from src.utils import clean_email, extract_urls, detect_ai_brands, analyze_domain, TRUSTED_AI_DOMAINS

# Load model (backward compatible)
@st.cache_resource
def load_model():
    model = pickle.load(open("model/phishing_model.pkl", "rb"))
    vectorizer = pickle.load(open("model/vectorizer.pkl", "rb"))
    return model, vectorizer

model, vectorizer = load_model()

# Detection lists
PHISHING_WORDS = ["verify", "urgent", "password", "bank", "account", "click", "login", "suspended"]
CREDENTIAL_KEYWORDS = ["password", "verify account", "login", "sign in"]
AI_BRANDS = ["chatgpt", "openai", "gemini", "copilot", "claude"]

st.set_page_config(page_title="AI Phishing Detector", layout="wide")
st.title("🤖 AI Phishing Email Detector v2.0")
st.markdown("**Advanced ML + Domain Spoofing + Explainable Risk Analysis**")

# Input
col1, col2 = st.columns([4, 1])
with col1:
    email = st.text_area("📧 Paste Email Content", height=200, 
                        placeholder="ChatGPT Premium expired. Verify at http://openai-security.com...")
with col2:
    example_btn = st.button("📋 Test Phishing Email")

if example_btn:
    email = """Subject: ChatGPT Account Issue

Dear User,

Your ChatGPT Premium account has expired. Please verify immediately at:
http://openai-security.com/verify?token=abc123

Enter your password to restore access. Urgent!

OpenAI Support Team"""

if st.button("🚨 ANALYZE", type="primary") and email.strip():
    email_lower = email.lower()
    
    # ML Analysis
    X = vectorizer.transform([email])
    prediction = model.predict(X)[0]
    ml_proba = model.predict_proba(X)[0][1]
    
    # Feature Extraction
    clean_text = clean_email(email)
    brands = detect_ai_brands(email)
    urls = extract_urls(email)
    
    # Domain Spoof Analysis
    domains = []
    for url in urls:
        domain_analysis = analyze_domain(url)
        domains.append(domain_analysis)
    
    suspicious_domains = [d for d in domains if d["spoof_detected"]]
    
    # Enhanced Risk Scoring (Updated weights)
    risk_score = 0
    reasons = []
    
    if brands:
        risk_score += 20
        reasons.append(f"🤖 **AI Brand**: {', '.join(brands)}")
    
    credential_count = sum(1 for kw in CREDENTIAL_KEYWORDS if kw in email_lower)
    if credential_count > 0:
        risk_score += 15
        reasons.append(f"🔐 **Credentials**: {credential_count} keywords")
    
    if ml_proba > 0.8:
        risk_score += 35
        reasons.append(f"🤖 **High ML Confidence**: {ml_proba:.1%}")
    else:
        risk_score += int(ml_proba * 20)
    
    if suspicious_domains:
        risk_score += 30
        reasons.append(f"🔗 **Spoofed Domains**: {len(suspicious_domains)}")
    
    # Results Layout
    st.divider()
    
    # Gauge Visualization
    col_gauge1, col_gauge2, col_gauge3 = st.columns(3)
    with col_gauge1:
        st.metric("Risk Score", f"{risk_score:.0f}/100")
    with col_gauge2:
        gauge_color = "inverse" if risk_score < 40 else "normal"
        st.progress(risk_score / 100, text=f"Risk Level")
    with col_gauge3:
        status = "✅ SAFE" if risk_score < 40 else "⚠️ SUSPICIOUS" if risk_score < 70 else "🚨 PHISHING"
        st.error(status) if risk_score >= 70 else st.success(status)
    
    # Top 3 Reasons
    st.subheader("📊 Top Detection Reasons")
    for i, reason in enumerate(reasons[:3], 1):
        st.write(f"{i}. {reason}")
    
    # Suspicious Word Highlighting
    if brands or PHISHING_WORDS:
        suspicious_terms = brands + [w for w in PHISHING_WORDS if w in email_lower]
        highlighted = re.sub(rf'\b({"|".join(suspicious_terms)})\b', 
                           r'<mark style="background-color: #ffeb3b">\1</mark>', 
                           email, flags=re.I)
        st.markdown("### 🔍 Suspicious Words **Highlighted**")
        st.markdown(highlighted, unsafe_allow_html=True)
    
    # Domain Analysis
    if urls:
        st.subheader("🌐 Domain Analysis")
        for domain_info in domains[:3]:  # Top 3
            col1, col2, col3 = st.columns(3)
            with col1:
                st.write(f"**{domain_info['domain']}**")
            with col2:
                color = "🟢" if not domain_info['spoof_detected'] else "🔴"
                st.write(f"{color} {domain_info['spoof_detected']}")
            with col3:
                st.caption(domain_info['reason'])
    
    # ML Details
    with st.expander("🔬 ML Model Details"):
        col1, col2 = st.columns(2)
        col1.metric("Prediction", "PHISHING" if prediction == 1 else "LEGITIMATE")
        col2.metric("ML Confidence", f"{ml_proba:.1%}")

st.markdown("---")
st.caption("Powered by Random Forest ML + Domain Spoof Detection")
