@echo off
title WebFootprint - Browser Forensics & Activity Analyzer
color 0b
echo ==============================================================================
echo           WebFootprint - Browser Forensics & Activity Analyzer
echo ==============================================================================
echo.
echo [*] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not found in your system PATH.
    echo Please install Python 3.10+ from python.org and add it to PATH.
    pause
    exit /b 1
)

echo [*] Initializing WebFootprint Digital Forensics Server...
echo [*] Server will be available at: http://127.0.0.1:5000
echo [*] Press Ctrl+C in this window to stop the server at any time.
echo.

python app.py

pause
