@echo off
cd /d c:\Users\ponshivavel\ai-phishing-email-detector
pip install uvicorn[standard] fastapi
uvicorn src.api:app --host 0.0.0.0 --port 8000 --reload
pause

