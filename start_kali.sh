#!/bin/bash
# Pentivo — Kali startup script
# Usage: bash start_kali.sh

cd ~/Pentivo
source .venv/bin/activate
git pull

echo "[*] Starting Metasploit RPC daemon..."
msfrpcd -P "$(grep MSF_RPC_PASSWORD .env | cut -d '=' -f2)" -a 127.0.0.1 -p 55553 &
sleep 5

echo "[*] Starting Pentivo Agent on port 8001..."
uvicorn pentest_engine.agent_main:app --host 0.0.0.0 --port 8001 --reload