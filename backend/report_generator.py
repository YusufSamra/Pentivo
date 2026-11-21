from datetime import datetime
from backend.database import (
    get_all_sessions, get_session_findings, get_session_executions
)


def _severity_color(severity: str) -> str:
    colors = {
        "CRITICAL": "#E63946",
        "HIGH": "#F77F00",
        "MEDIUM": "#FCBF49",
        "LOW": "#90BE6D",
    }
    return colors.get((severity or "").upper(), "#999999")


def _get_session_info(session_id: int) -> dict:
    for s in get_all_sessions():
        if s["id"] == session_id:
            return s
    return {}


def generate_html_report(session_id: int) -> str:
    session = _get_session_info(session_id)
    findings = get_session_findings(session_id)
    executions = get_session_executions(session_id)

    total_findings = len(findings)
    critical_count = sum(1 for f in findings if (f.get("severity") or "").upper() == "CRITICAL")
    executable_count = sum(1 for f in findings if f.get("ready_to_execute"))
    successful_execs = sum(1 for e in executions if e.get("success"))
    root_achieved = sum(1 for e in executions if e.get("is_root"))

    findings_rows = ""
    for f in findings:
        color = _severity_color(f.get("severity"))
        ready = "✓" if f.get("ready_to_execute") else "—"
        findings_rows += f"""
        <tr>
            <td>{f.get('host', '')}</td>
            <td>{f.get('port', '')}</td>
            <td>{f.get('product', '')} {f.get('version', '') or ''}</td>
            <td>{f.get('cve_id', '')}</td>
            <td><span style="color:{color};font-weight:bold;">{f.get('severity', '')}</span></td>
            <td>{f.get('cvss_score', '')}</td>
            <td>{f.get('ai_severity', '')}</td>
            <td>{f.get('priority_score', '')}</td>
            <td style="text-align:center;">{ready}</td>
        </tr>"""

    exec_rows = ""
    for e in executions:
        status_text = "Success" if e.get("success") else "Failed"
        status_color = "#2A9D8F" if e.get("success") else "#E63946"
        root_text = "ROOT" if e.get("is_root") else (e.get("current_user") or "—")
        exec_rows += f"""
        <tr>
            <td>{e.get('host', '')}</td>
            <td>{e.get('cve_id', '')}</td>
            <td style="font-family:monospace;font-size:12px;">{e.get('module', '')}</td>
            <td><span style="color:{status_color};font-weight:bold;">{status_text}</span></td>
            <td>{root_text}</td>
            <td>{e.get('executed_at', '')}</td>
        </tr>"""

    if not exec_rows:
        exec_rows = '<tr><td colspan="6" style="text-align:center;color:#999;">No executions recorded</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pentivo Report — Session {session_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 40px; background: #f4f6f9; color: #1f2937; }}
        .container {{ max-width: 1100px; margin: 0 auto; background: #fff; padding: 40px; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }}
        h1 {{ color: #121A2E; border-bottom: 3px solid #00C896; padding-bottom: 12px; }}
        h2 {{ color: #121A2E; margin-top: 36px; }}
        .meta {{ color: #5B6B82; font-size: 14px; margin-bottom: 24px; }}
        .summary {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 24px 0; }}
        .stat {{ flex: 1; min-width: 150px; background: #E6F7F1; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat .num {{ font-size: 32px; font-weight: bold; color: #0E8F6F; }}
        .stat .label {{ font-size: 13px; color: #5B6B82; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 14px; }}
        th {{ background: #121A2E; color: #fff; padding: 10px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #eee; }}
        tr:hover {{ background: #f9f9f9; }}
        .footer {{ margin-top: 40px; color: #999; font-size: 12px; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Pentivo — Penetration Test Report</h1>
        <div class="meta">
            Session #{session_id} &nbsp;·&nbsp;
            Target: {session.get('target_range', 'N/A')} &nbsp;·&nbsp;
            Started: {session.get('started_at', 'N/A')} &nbsp;·&nbsp;
            Generated: {datetime.utcnow().isoformat()}
        </div>

        <div class="summary">
            <div class="stat"><div class="num">{total_findings}</div><div class="label">Total Findings</div></div>
            <div class="stat"><div class="num">{critical_count}</div><div class="label">Critical</div></div>
            <div class="stat"><div class="num">{executable_count}</div><div class="label">Executable</div></div>
            <div class="stat"><div class="num">{successful_execs}</div><div class="label">Successful Exploits</div></div>
            <div class="stat"><div class="num">{root_achieved}</div><div class="label">Root Access</div></div>
        </div>

        <h2>Discovered Vulnerabilities</h2>
        <table>
            <thead>
                <tr>
                    <th>Host</th><th>Port</th><th>Service</th><th>CVE</th>
                    <th>Severity</th><th>CVSS</th><th>AI Severity</th>
                    <th>Priority</th><th>Ready</th>
                </tr>
            </thead>
            <tbody>{findings_rows}</tbody>
        </table>

        <h2>Execution Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Host</th><th>CVE</th><th>Module</th>
                    <th>Status</th><th>Access</th><th>Time</th>
                </tr>
            </thead>
            <tbody>{exec_rows}</tbody>
        </table>

        <div class="footer">
            Generated by Pentivo — AI Autonomous Pentest Decision Lab
        </div>
    </div>
</body>
</html>"""

    return html