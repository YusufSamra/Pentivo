import sqlite3
import json
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).parent.parent / "pentivo.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_range TEXT,
            started_at TEXT,
            status TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            host TEXT,
            port TEXT,
            service TEXT,
            product TEXT,
            version TEXT,
            cve_id TEXT,
            cvss_score REAL,
            severity TEXT,
            ai_severity TEXT,
            exploitability_estimate TEXT,
            priority_score REAL,
            ready_to_execute INTEGER,
            FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            host TEXT,
            cve_id TEXT,
            module TEXT,
            executed_at TEXT,
            success INTEGER,
            session_created INTEGER,
            current_user TEXT,
            is_root INTEGER,
            raw_result TEXT,
            FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
        )
    """)

    conn.commit()
    conn.close()


def create_scan_session(target_range: str) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_sessions (target_range, started_at, status) VALUES (?, ?, ?)",
        (target_range, datetime.utcnow().isoformat(), "running")
    )
    session_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return session_id


def update_session_status(session_id: int, status: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE scan_sessions SET status = ? WHERE id = ?",
        (status, session_id)
    )
    conn.commit()
    conn.close()


def save_findings(session_id: int, ranked_list: list):
    conn = get_connection()
    cursor = conn.cursor()
    for item in ranked_list:
        cursor.execute("""
            INSERT INTO findings (
                session_id, host, port, service, product, version,
                cve_id, cvss_score, severity, ai_severity,
                exploitability_estimate, priority_score, ready_to_execute
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            item.get("host"),
            item.get("port"),
            item.get("service"),
            item.get("product"),
            item.get("version"),
            item.get("cve_id"),
            item.get("cvss_score"),
            item.get("severity"),
            item.get("ai_severity"),
            item.get("exploitability_estimate"),
            item.get("priority_score"),
            1 if item.get("ready_to_execute") else 0,
        ))
    conn.commit()
    conn.close()


def save_execution(session_id: int, host: str, cve_id: str, module: str,
                   result: dict, analysis: dict):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO executions (
            session_id, host, cve_id, module, executed_at,
            success, session_created, current_user, is_root, raw_result
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        session_id,
        host,
        cve_id,
        module,
        datetime.utcnow().isoformat(),
        1 if result.get("success") else 0,
        1 if result.get("session_created") else 0,
        analysis.get("current_user"),
        1 if analysis.get("is_root") else 0,
        json.dumps(result, ensure_ascii=False),
    ))
    conn.commit()
    conn.close()


def get_session_findings(session_id: int) -> list:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM findings WHERE session_id = ? ORDER BY priority_score DESC",
        (session_id,)
    )
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_session_executions(session_id: int) -> list:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM executions WHERE session_id = ? ORDER BY executed_at",
        (session_id,)
    )
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_all_sessions() -> list:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_sessions ORDER BY started_at DESC")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows