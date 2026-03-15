from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict
import pickle
import numpy as np
import sqlite3
from datetime import datetime
from src.utils import clean_email, extract_urls, detect_ai_brands, analyze_domain, TRUSTED_AI_DOMAINS
import uvicorn
import json
import os

# --------------------------------------------------
# APP SETUP
# --------------------------------------------------

app = FastAPI(title="AI Phishing Detector API v2.0", version="2.0")

# Base directory (important for cloud deployment)
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

# --------------------------------------------------
# LOAD ML MODEL
# --------------------------------------------------

try:
    model = pickle.load(open(os.path.join(BASE_DIR, "model", "phishing_model.pkl"), "rb"))
    vectorizer = pickle.load(open(os.path.join(BASE_DIR, "model", "vectorizer.pkl"), "rb"))
    print("✅ Model loaded successfully")
except Exception as e:
    print(f"❌ Model loading error: {e}")
    model = None
    vectorizer = None

# --------------------------------------------------
# REQUEST / RESPONSE MODELS
# --------------------------------------------------

class EmailRequest(BaseModel):
    email_text: str


class AnalysisResponse(BaseModel):
    prediction: str
    risk_score: float
    ml_probability: float
    reasons: List[str]
    detected_brands: List[str]
    domains_analysis: List[Dict]
    num_urls: int
    clean_text: str


# --------------------------------------------------
# DATABASE LOGGER
# --------------------------------------------------

def log_analysis(email_text: str, prediction: int, risk_score: float, domains: str, timestamp):
    
    conn = sqlite3.connect('phishing_logs.db')
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY,
            email_text TEXT,
            prediction TEXT,
            risk_score REAL,
            domains TEXT,
            timestamp TEXT
        )
    """)

    cursor.execute(
        "INSERT INTO analyses VALUES (NULL, ?, ?, ?, ?, ?)",
        (
            email_text[:500],
            "PHISHING" if prediction == 1 else "LEGITIMATE",
            risk_score,
            domains,
            timestamp.isoformat()
        )
    )

    conn.commit()
    conn.close()


# --------------------------------------------------
# MAIN DETECTION ENDPOINT
# --------------------------------------------------

@app.post("/analyze-email", response_model=AnalysisResponse)
async def analyze_email(request: EmailRequest):

    if model is None or vectorizer is None:
        raise HTTPException(status_code=500, detail="Model not available")

    email = request.email_text.lower()

    # ML prediction
    X = vectorizer.transform([request.email_text])
    prediction = model.predict(X)[0]
    ml_proba = model.predict_proba(X)[0][1]

    # Feature extraction
    clean_text = clean_email(request.email_text)
    brands = detect_ai_brands(request.email_text)
    urls = extract_urls(request.email_text)
    domains_analysis = [analyze_domain(url) for url in urls]

    # --------------------------------------------------
    # RISK SCORING SYSTEM
    # --------------------------------------------------

    risk_score = 0
    reasons = []

    if brands:
        risk_score += 20
        reasons.append(f"🤖 AI Brand Detected: {brands[0]}")

    suspicious = [d for d in domains_analysis if d.get("spoof_detected")]

    if suspicious:
        risk_score += 30
        reasons.append(f"🔗 Spoofed Domain: {suspicious[0].get('domain')}")

    if ml_proba > 0.7:
        risk_score += 35
    else:
        risk_score += ml_proba * 25

    prediction_label = "PHISHING" if risk_score >= 50 or prediction == 1 else "LEGITIMATE"

    # Log after scoring (important fix)
    log_analysis(
        request.email_text,
        prediction,
        risk_score,
        json.dumps(domains_analysis),
        datetime.now()
    )

    return AnalysisResponse(
        prediction=prediction_label,
        risk_score=round(risk_score, 1),
        ml_probability=round(ml_proba, 3),
        reasons=reasons[:3],
        detected_brands=brands,
        domains_analysis=domains_analysis,
        num_urls=len(urls),
        clean_text=clean_text[:200] + "..."
    )


# --------------------------------------------------
# ANALYTICS ENDPOINT
# --------------------------------------------------

@app.get("/analytics")
async def analytics():

    conn = sqlite3.connect('phishing_logs.db')
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM analyses")
    total = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM analyses WHERE prediction="PHISHING"')
    phishing = cursor.fetchone()[0]

    conn.close()

    return {
        "total_analyzed": total,
        "phishing_detected": phishing
    }


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "healthy"}


# --------------------------------------------------
# RUN SERVER
# --------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
