@echo off
cd /d D:\Pentivo
call .venv\Scripts\activate
git pull
echo [*] Starting Pentivo Backend on port 8000...
uvicorn backend.main:app --reload