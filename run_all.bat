@echo off
echo ========================================================
echo ThreatLens AI - Complete System Launcher
echo ========================================================
echo 1. Launching MongoDB in new window...
start "ThreatLens - MongoDB" cmd /c "start_mongodb.bat"
timeout /t 3 >nul

echo 2. Launching FastAPI Backend in new window...
start "ThreatLens - Backend" cmd /c "run_backend.bat"
timeout /t 3 >nul

echo 3. Launching React Frontend in new window...
start "ThreatLens - Frontend" cmd /c "run_frontend.bat"

echo ========================================================
echo All services launched!
echo - Frontend UI:  http://localhost:5173
echo - API Docs:     http://localhost:8000/docs
echo ========================================================
pause
