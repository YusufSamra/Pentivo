import requests
from backend.logger_config import get_logger

logger = get_logger("orchestrator")
from backend.database import (
    create_scan_session, update_session_status,
    save_findings, save_execution
)

from backend.config import KALI_AGENT_URL, backend_timeout_for

def run_full_pipeline(target_range: str, ai_decide_url: str) -> dict:
    session_id = create_scan_session(target_range)

    logger.info(f"=== Full pipeline started: session {session_id}, target {target_range} ===")

    steps_log = []

    try:
        # --- Phase 1 + 2: Enumerate (discover is implicit in the IP list) ---
        steps_log.append("Enumerating services...")
        enum_res = requests.post(
            f"{KALI_AGENT_URL}/enumerate",
            json={"host_range": target_range},
            timeout=backend_timeout_for(target_range)       
              )
        enum_res.raise_for_status()
        enum_data = enum_res.json()

        # --- Phase 3: CVE enrichment (via Backend's own /analyze logic) ---
        steps_log.append("Enriching with CVEs...")
        from pentest_engine.cve_lookup import enrich_with_cves
        enriched = enrich_with_cves(enum_data["results"])

        # --- Phase 4: AI assessment ---
        steps_log.append("AI assessment in progress...")
        from ai_service.decision_engine import assess_all
        assessments = assess_all(enriched)

        # --- Phase 5: Ranking ---
        steps_log.append("Ranking vulnerabilities...")
        from pentest_engine.ranking_engine import rank_assessments
        ranked_result = rank_assessments(assessments)
        ranked = ranked_result["ranked"]

        # Save findings to DB
        save_findings(session_id, ranked)

        # --- Phase 6 + 7: Execute top ready item + analyze ---
        execution_summary = None
        target_item = next((item for item in ranked if item.get("ready_to_execute")), None)

        if target_item:
            steps_log.append(f"Executing {target_item['cve_id']} on {target_item['host']}...")
            exec_res = requests.post(
                f"{KALI_AGENT_URL}/execute",
                json={"target": target_item["host"], "exploit_info": target_item["exploit_info"]},
                timeout=120
            )
            exec_res.raise_for_status()
            execution_result = exec_res.json()

            steps_log.append("Analyzing execution result...")
            analysis_res = requests.post(
                f"{KALI_AGENT_URL}/analyze_result",
                json={"execution_result": execution_result},
                timeout=60
            )
            analysis_res.raise_for_status()
            analysis = analysis_res.json()

            save_execution(
                session_id,
                target_item["host"],
                target_item["cve_id"],
                target_item["exploit_info"]["module"],
                execution_result,
                analysis
            )
            execution_summary = {
                "executed_item": target_item,
                "result": execution_result,
                "analysis": analysis
            }
        else:
            steps_log.append("No executable vulnerability found.")

        update_session_status(session_id, "completed")

        logger.info(f"=== Pipeline completed: session {session_id}, {len(ranked)} findings ===")

        return {
            "session_id": session_id,
            "status": "completed",
            "steps": steps_log,
            "total_findings": len(ranked),
            "execution": execution_summary,
        }

    except Exception as e:
        update_session_status(session_id, "failed")
        logger.error(f"Pipeline failed for session {session_id}: {e}")
        return {
            "session_id": session_id,
            "status": "failed",
            "steps": steps_log,
            "error": str(e),
        }