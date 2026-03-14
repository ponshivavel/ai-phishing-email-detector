import streamlit as st
import pickle
import re

# Load model and vectorizer (backward compatible)
model = pickle.load(open("model/phishing_model.pkl", "rb"))
vectorizer = pickle.load(open("model/vectorizer.pkl", "rb"))

# Detection lists
phishing_words = ["verify", "urgent", "password", "bank", "account", "click", "login", "suspended"]
ai_brands = ["chatgpt", "openai", "gemini", "google ai", "ai assistant", "claude", "bard", "microsoft ai", "copilot", "huggingface", "anthropic", "midjourney"]
suspicious_app_links = ["apps.apple.com", "play.google.com", "appstore", "googleplay", "microsoft.store"]
credential_keywords = ["password", "verify account", "login", "connect facebook", "sign in", "enter password", "confirm your identity", "update payment", "secure account"]

st.title("🤖 AI-Powered Phishing Email Detector")
st.markdown("### 🔍 Advanced Detection: ML + AI Brand Impersonation + URL Spoofing")

email = st.text_area("Paste Email Content Here", height=200, placeholder="Your ChatGPT account is suspended. Verify immediately at openai-security.com...")

if st.button("🚨 ANALYZE EMAIL", type="primary"):
    if not email.strip():
        st.warning("Please paste an email to analyze!")
    else:
        email_lower = email.lower()
        
        # ML Prediction (core)
        X = vectorizer.transform([email])
        prediction = model.predict(X)[0]
        prediction_proba = model.predict_proba(X)[0][1]
        
        # Rule-based detections
        detected_brands = [b for b in ai_brands if b in email_lower]
        detected_app_links = [l for l in suspicious_app_links if l in email_lower]
        detected_credentials = [k for k in credential_keywords if k in email_lower]
        detected_phishing = [w for w in phishing_words if w in email_lower]
        
        # Enhanced Risk Score
        risk_score = 0
        reasons = []
        
        if detected_brands:
            risk_score += 30
            reasons.append(f"🤖 AI Brand Impersonation: {', '.join(detected_brands)}")
        if detected_app_links:
            risk_score += 30
            reasons.append("📱 Suspicious App Store Link")
        if detected_credentials:
            risk_score += 20
            reasons.append(f"🔐 Credential Harvest: {len(detected_credentials)} keywords")
        risk_score += min(prediction_proba * 20, 20)
        reasons.append(f"🤖 ML Probability: {prediction_proba:.1%}")
        
        # Results
        st.divider()
        
        col1, col2 = st.columns([1, 3])
        with col1:
            st.metric("Risk Score", f"{risk_score:.0f}/100", delta=None)
        with col2:
            if risk_score >= 70:
                st.error("🚨 **HIGH RISK** - Phishing Detected")
            elif risk_score >= 40:
                st.warning("⚠️ **MEDIUM RISK** - Suspicious")
            else:
                st.success("✅ **LOW RISK** - Safe")
        
        # Detailed Reasons
        with st.expander("📋 Detection Breakdown", expanded=True):
            for reason in reasons:
                st.write(f"• **{reason}**")
        
        # Highlight Suspicious Content
        if detected_brands or detected_phishing:
            st.subheader("🔍 Suspicious Terms Found")
            highlighted = re.sub(rf'\b({"|".join(detected_brands + detected_phishing)})\b', r'**\1**', email_lower, flags=re.I)
            st.text_area("Highlighted", highlighted, height=100, disabled=True)
