@echo off
echo Stopping ELK Stack...
cd /d "%~dp0"
docker-compose down
echo Done!
pause