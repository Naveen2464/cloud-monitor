@echo off
echo ============================================
echo   Starting ELK Stack for Cloud Monitor
echo ============================================
echo.

cd /d "%~dp0"

echo [1] Creating log files if not exist...
if not exist "..\app.log" type nul > "..\app.log"
if not exist "..\alerts.log" type nul > "..\alerts.log"

echo [2] Starting Docker containers...
docker-compose up -d

echo.
echo [3] Waiting 30 seconds for services to start...
timeout /t 30 /nobreak

echo.
echo [4] Checking status...
docker-compose ps

echo.
echo ============================================
echo   ELK Stack is starting!
echo   Elasticsearch: http://localhost:9200
echo   Kibana:        http://localhost:5601
echo   (Kibana takes 1-2 minutes to fully load)
echo ============================================
echo.
echo Now run in another terminal:
echo   python ..\app.py
echo.
pause