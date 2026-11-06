@echo off
title AI-Assisted Secure Code Reviewer
echo ========================================================
echo   AI-Assisted Secure Code Reviewer - Launching Server
echo ========================================================
echo.

set PYTHON_CMD=python
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    set "PYTHON_CMD=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
) else (
    where py >nul 2>&1 && set "PYTHON_CMD=py -3.12"
)

echo Starting FastAPI server on http://127.0.0.1:8000 ...
echo (Press Ctrl + C to stop the server)
echo.

REM Start the server in the background and wait 2 s before opening the browser
start "" /B "%PYTHON_CMD%" -m uvicorn api.index:app --host 127.0.0.1 --port 8000
timeout /t 2 /nobreak >nul
start http://127.0.0.1:8000

REM Keep this window alive so the server stays running
"%PYTHON_CMD%" -m uvicorn api.index:app --host 127.0.0.1 --port 8000
pause
