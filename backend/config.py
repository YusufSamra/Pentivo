import os
from dotenv import load_dotenv

load_dotenv()

# --- Network ---
KALI_AGENT_URL = os.getenv("KALI_AGENT_URL", "http://localhost:8001")
ALLOWED_NETWORK_CIDR = os.getenv("ALLOWED_NETWORK_CIDR", "192.168.243.0/24")

# --- AI Service ---
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b-instruct")

# --- NVD ---
NVD_API_KEY = os.getenv("NVD_API_KEY")

# --- Metasploit RPC ---
MSF_RPC_PASSWORD = os.getenv("MSF_RPC_PASSWORD")
MSF_RPC_PORT = int(os.getenv("MSF_RPC_PORT", "55553"))
MSF_RPC_HOST = os.getenv("MSF_RPC_HOST", "127.0.0.1")

# --- Timeouts (seconds) ---
PER_HOST_SCAN_TIMEOUT = int(os.getenv("PER_HOST_SCAN_TIMEOUT", "90"))
TIMEOUT_BUFFER = int(os.getenv("TIMEOUT_BUFFER", "60"))
EXECUTION_TIMEOUT = int(os.getenv("EXECUTION_TIMEOUT", "120"))


def backend_timeout_for(target_range: str) -> int:
    """حساب timeout ديناميكي حسب عدد الأجهزة بدل رقم ثابت."""
    host_count = len([t for t in target_range.split(",") if t.strip()])
    return (PER_HOST_SCAN_TIMEOUT * max(host_count, 1)) + TIMEOUT_BUFFER