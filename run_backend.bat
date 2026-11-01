@echo off
echo ========================================================
echo Starting ThreatLens AI FastAPI Backend Server...
echo ========================================================
.\venv\Scripts\uvicorn.exe backend.app.main:app --host 127.0.0.1 --port 8000 --reload
pause
