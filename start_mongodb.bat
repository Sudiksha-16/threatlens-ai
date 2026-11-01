@echo off
echo ========================================================
echo Starting Local MongoDB Server for ThreatLens AI...
echo ========================================================
if not exist "data\db" mkdir "data\db"
"C:\Program Files\MongoDB\Server\6.0\bin\mongod.exe" --dbpath data\db
pause
