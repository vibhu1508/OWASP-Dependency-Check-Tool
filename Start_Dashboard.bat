@echo off
echo ==========================================
echo    STARTING DASHBOARD SERVER (PORT 7890)
echo ==========================================
echo.
echo Access your dashboard at: http://localhost:7890
echo.
python -m http.server 7890
pause
