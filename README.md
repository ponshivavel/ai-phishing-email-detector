# AI Phishing Email Detector 🚀

## 🎯 Overview
Advanced ML-powered phishing detector with:
- **Random Forest classifier** trained on Enron dataset
- **NLP preprocessing** (stemming, stopwords)
- **AI Brand Impersonation detection** (ChatGPT, OpenAI)
- **Domain spoof detection** (Levenshtein similarity)
- **FastAPI backend** + **Streamlit UI**
- **SQLite logging** for analytics

## 🔥 Live Demo
```
UI: http://localhost:8503
API: http://localhost:8000/docs
```

## 📦 Structure
```
├── app_enhanced.py (UI with gauge + highlighting)
├── src/api.py (FastAPI + logging)
├── src/utils.py (NLP + spoofing)
├── model/train.py (RF training)
├── data/phishing_email.csv (82k dataset)
└── requirements.txt
```

## 🚀 Quick Start
```
pip install -r requirements.txt
python model/train.py  # Train model
.\run_app.bat         # UI
.\run_api.bat         # API
```

## 🧠 How It Works
```
Email → NLP Clean → TF-IDF → Random Forest → ML Score
     ↳ URL Extract → Domain Spoof → Similarity Score
     ↳ Brand Match → Rule Score
     ↓
Composite Risk + Explainable Reasons
```

**Risk Formula**:
```
20 (AI Brand) + 15 (Credentials) + 35 (High ML) + 30 (Spoof Domain)
```

## 📊 Analytics
```
GET /analytics → {"phishing_detected": 42, "avg_risk": 72.5}
DB: phishing_logs.db
```

## 🔬 Test Results
```
Input: "ChatGPT expired openai-security.com/verify"
Output: Risk 85 🚨 + "openai-security.com spoof (sim 0.78)"
```

**Production Ready** - ML + API + Logging + UI!
