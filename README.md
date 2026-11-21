# Pentivo — AI Autonomous Pentest Decision Lab

نظام يقوم بدورة اختبار الاختراق بشكل شبه تلقائي، حيث يحلل الذكاء الاصطناعي الثغرات ويتخذ القرار، بينما يظل التنفيذ محصوراً في كود ثابت خاضع للمراجعة البشرية.

**المبدأ الجوهري:** الذكاء الاصطناعي يقرر فقط — الكود الثابت ينفذ فقط.

## المعمارية (3 أجهزة)
- **Laptop 1 (Windows):** Backend + Kali VM (Nmap + Metasploit)
- **Laptop 2:** Isolated Lab (Metasploitable 2/3) على شبكة Host-only معزولة
- **Laptop 3:** AI Machine (Ollama + qwen2.5:7b-instruct)

مربوطة عبر Tailscale VPN.

## المراحل (Pipeline)
1. Recon (Nmap)
2. Enumeration
3. CVE Analysis (NVD)
4. AI Decision (LangChain + Ollama)
5. Ranking
6. Execution (Metasploit RPC)
7. Result Analysis
8. Decision Loop

## التشغيل

### Windows (Backend)
cd D:\Pentivo
.venv\Scripts\activate
uvicorn backend.main:app --reload

### Kali (Agent)
bash start_kali.sh

### AI Machine
Ollama يعمل تلقائياً في الخلفية.

## الواجهة
افتح frontend/dashboard.html في المتصفح بعد تشغيل الـ Backend.

## التقنيات
FastAPI · LangChain · Ollama · Nmap · Metasploit · NVD API · SQLite · Tailscale

## الأمان
- فصل القرار عن التنفيذ
- قائمة بيضاء يدوية للـ Modules المعتمدة
- تحقق مزدوج من نطاق الأهداف
- عزل شبكي كامل للأهداف
- تسجيل مركزي لكل العمليات