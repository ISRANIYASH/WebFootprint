# WebFootprint - Digital Forensics Server Launcher
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "          WebFootprint - Browser Forensics & Activity Analyzer" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Starting Digital Forensics Server on http://127.0.0.1:5000 ..." -ForegroundColor Green
Write-Host "[*] Press Ctrl+C to stop the server." -ForegroundColor Yellow
Write-Host ""

python app.py
