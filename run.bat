@echo off
title AI-Assisted Secure Code Reviewer
echo ========================================================
echo   AI-Assisted Secure Code Reviewer - Launching Server
echo ========================================================
echo.
echo Opening http://localhost:8000 in your browser...
start http://localhost:8000
echo.
echo Starting FastAPI & React Web Server...
echo (Press Ctrl + C to stop the server)
echo.
python -m uvicorn api.index:app --reload --host 127.0.0.1 --port 8000
pause
