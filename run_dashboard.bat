@echo off
echo ==========================================
echo    SOC Level 2 Dashboard
echo ==========================================
echo.

REM Check admin privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [+] Running with administrator privileges
) else (
    echo [!] Warning: Not running as administrator
    echo     Some features may be limited
    echo.
)

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python not found! Please install Python 3.8+
    pause
    exit /b
)

REM Install dependencies if needed
if not exist .deps_installed (
    echo [+] Installing dependencies...
    pip install -r requirements_dashboard.txt
    echo. > .deps_installed
)

echo [+] Starting SOC Dashboard...
echo [+] Browser will open automatically
echo [+] URL: http://127.0.0.1:5000
echo.

python soc_dashboard.py

pause
