import os
import json
from dotenv import load_dotenv
from langchain_ollama import OllamaLLM

load_dotenv()

from backend.config import OLLAMA_URL, OLLAMA_MODEL

llm = OllamaLLM(
    model=OLLAMA_MODEL,
    base_url=OLLAMA_URL,
    format="json",
    temperature=0.1,
    client_kwargs={"timeout": 90},
)

def build_vulnerability_prompt(context: dict) -> str:
    return f"""You are a cybersecurity risk analysis engine inside an automated penetration testing system.

You will be given ONE discovered vulnerability. Analyze it and respond with ONLY a JSON object, no explanation outside the JSON, using exactly this schema:

{{
  "ai_severity": one of ["Critical", "High", "Medium", "Low"],
  "exploitability_estimate": one of ["Easy", "Moderate", "Hard"],
  "reasoning": a short explanation, maximum 2 sentences
}}

Vulnerability details:
- Host: {context.get('host')}
- Port / Protocol: {context.get('port')}/{context.get('protocol')}
- Service: {context.get('service')}
- Product: {context.get('product')}
- Version: {context.get('version')}
- CVE ID: {context.get('cve_id')}
- CVSS Score: {context.get('cvss_score')}
- Official NVD Severity: {context.get('severity')}
- CVE Description: {context.get('description')}

Respond with the JSON object only."""


def _normalize_label(value, allowed):
    if not isinstance(value, str):
        return None
    value_clean = value.strip().lower()
    for option in allowed:
        if option.lower() == value_clean:
            return option
    return None


def assess_vulnerability(context: dict) -> dict:
    prompt = build_vulnerability_prompt(context)

    try:
        raw = llm.invoke(prompt)
    except Exception as e:
        return {
            **context,
            "error": f"AI call failed: {e}",
        }

    try:
        ai_result = json.loads(raw)
    except json.JSONDecodeError:
        return {
            **context,
            "error": "Failed to parse AI response as JSON",
            "raw_response": raw
        }

    ai_result["ai_severity"] = _normalize_label(
        ai_result.get("ai_severity"), ["Critical", "High", "Medium", "Low"]
    )
    ai_result["exploitability_estimate"] = _normalize_label(
        ai_result.get("exploitability_estimate"), ["Easy", "Moderate", "Hard"]
    )

    return {**context, **ai_result}


def assess_all(enriched_results: list, limit: int = None) -> list:
    assessments = []

    for host_entry in enriched_results:
        host = host_entry.get("host")
        for svc in host_entry.get("services", []):
            for cve in svc.get("cves", []):
                if not cve.get("cve_id"):
                    continue

                context = {
                    "host": host,
                    "port": svc.get("port"),
                    "protocol": svc.get("protocol"),
                    "service": svc.get("service"),
                    "product": svc.get("product"),
                    "version": svc.get("version"),
                    "cve_id": cve.get("cve_id"),
                    "cvss_score": cve.get("cvss_score"),
                    "severity": cve.get("severity"),
                    "description": cve.get("description"),
                }

                result = assess_vulnerability(context)
                assessments.append(result)

                if limit and len(assessments) >= limit:
                    return assessments

    return assessments
