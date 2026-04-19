@echo off
echo ==========================================
echo    OWASP Dependency Check - SCAN STARTING
echo ==========================================
echo.
set /p API_KEY="Enter your NVD API Key (or press enter if already configured): "
if "%API_KEY%"=="" set API_KEY=e8ae1518-7273-46e6-86ea-18379c4a8835

.\dc-v12\dependency-check\bin\dependency-check.bat --project "Demo" --scan "presentation_demo" --format HTML --out "./report" --nvdApiKey "%API_KEY%" --noupdate --enableExperimental --disableOssIndex
echo.
echo ==========================================
echo    SCAN COMPLETE! 
echo    Check report/dependency-check-report.json
echo ==========================================
pause
