import streamlit as st
import pickle
import re

model = pickle.load(open("model/phishing_model.pkl", "rb"))
vectorizer = pickle.load(open("model/vectorizer.pkl", "rb"))

# Original phishing keywords
phishing_words = [
    "verify", "urgent", "password",
    "bank", "account", "click",
    "login", "suspended"
]

# AI Brand Impersonation Detection Module
ai_brands = [
    "chatgpt", "openai", "gemini", 
    "google ai", "ai assistant", "claude",
    "bard", "microsoft ai", "copilot",
    "huggingface", "anthropic", "midjourney"
]

# Suspicious app store links
suspicious_app_links = [
    "apps.apple.com", "play.google.com", 
    "appstore", "googleplay", "microsoft.store"
]

# Credential harvesting keywords
credential_keywords = [
    "password", "verify account", 
    "login", "connect facebook", "sign in", "enter password",
    "confirm your identity", "update payment", "secure account"
]

st.title("AI-Powered Phishing Email Detector")
st.markdown("### 🔍 Advanced Phishing Detection with AI Brand Impersonation Analysis")

email = st.text_area("Paste Email Content", height=150)

if st.button("🔍 Check Email"):
    email_lower = email.lower()
    
    # 1. ML Model Prediction
    X = vectorizer.transform([email])
    prediction = model.predict(X)
    prediction_proba = model.predict_proba(X)[0]
    
    # 2. Detect AI Brand Mentions
    detected_brands = [brand for brand in ai_brands if brand in email_lower]
    
    # 3. Detect Suspicious App Links
    detected_app_links = [link for link in suspicious_app_links if link in email_lower]
    
    # 4. Detect Credential Harvesting Attempts
    detected_credential_keywords = [kw for kw in credential_keywords if kw in email_lower]
    
    # 5. Detect Suspicious Phishing Words
    detected_phishing_words = [w for w in phishing_words if w in email_lower]
    
    # Calculate Risk Score
    risk_score = 0
    reasons = []
    
    if detected_brands:
        risk_score += 30
        reasons.append(f"AI Brand impersonation detected: {', '.join(detected_brands)}")
    
    if detected_app_links:
        risk_score += 30
        reasons.append(f"Suspicious app download link found")
    
    if detected_credential_keywords:
        risk_score += 20
        reasons.append(f"Credential harvesting attempt: {', '.join(detected_credential_keywords)}")
    
    if prediction[0] == 1:
        risk_score += 20
        reasons.append(f"ML model predicts phishing (confidence: {prediction_proba[1]*100:.1f}%)")
    
    # Display Results
    st.divider()
    
    # Risk Score Display
    if risk_score >= 70:
        st.error(f"🚨 High Risk! Phishing Risk Score: {risk_score}/100")
    elif risk_score >= 40:
        st.warning(f"⚠️ Medium Risk! Phishing Risk Score: {risk_score}/100")
    else:
        st.success(f"✅ Low Risk! Phishing Risk Score: {risk_score}/100")
    
    # Final Classification
    if prediction[0] == 1 or risk_score >= 50:
        st.error("⚠️ PHISHING EMAIL DETECTED")
    else:
        st.success("✅ SAFE EMAIL")
    
    # Explainable AI Output
    if reasons:
        st.markdown("### 📋 Detection Reasons:")
        for reason in reasons:
            st.write(f"• {reason}")
    
    # AI Brand Detection Results
    if detected_brands:
        st.warning("🤖 AI Brand Impersonation Detected!")
        st.write(f"Brands found: {', '.join(detected_brands)}")
        st.markdown("⚠️ Attackers often use trusted AI brand names to trick users!")
    
    # Suspicious Link Detection
    if detected_app_links:
        st.warning("📱 Suspicious App Store Link Detected!")
        st.markdown("⚠️ Be cautious of links to app stores - they may be fake login pages!")
    
    # Credential Harvesting Detection
    if detected_credential_keywords:
        st.warning("🔐 Credential Harvesting Attempt Detected!")
        st.markdown("⚠️ This email is requesting sensitive credentials!")
    
    # Traditional keyword warnings
    if detected_phishing_words and not detected_brands:
        st.warning("🚩 Suspicious keywords detected:")
        st.write(detected_phishing_words)

# End of app.py - Fixed syntax error at line 125


</parameter>
</create_file>
