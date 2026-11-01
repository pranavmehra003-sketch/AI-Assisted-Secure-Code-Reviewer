@echo off
title AI-Assisted Secure Code Reviewer
echo ========================================================
echo   AI-Assisted Secure Code Reviewer - Launching Server
echo ========================================================
echo.
echo Opening http://localhost:8000 in your browser...
start http://localhost:8000
echo.
echo Starting FastAPI and React Web Server on http://127.0.0.1:8000...
echo (Press Ctrl + C to stop the server)
echo.

set PYTHON_CMD=python
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    set "PYTHON_CMD=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
) else (
    where py >nul 2>&1 && set "PYTHON_CMD=py -3.12"
)

"%PYTHON_CMD%" -m uvicorn api.index:app --host 127.0.0.1 --port 8000
pause
