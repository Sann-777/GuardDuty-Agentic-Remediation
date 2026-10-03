"""
main.py - Autonomous GuardDuty Incident Response Pipeline
==========================================================
Autonomous agentic incident response workflow:
1. Fetch Node: Retrieve GuardDuty finding payloads (AWS or local).
2. Rule Evaluator Node (Filter / Condition Gatekeeper):
   - Evaluates findings against severity and threat rules.
   - Condition = FALSE: Terminates workflow cleanly (no remediation needed).
   - Condition = TRUE: Proceeds to the Remediation Loop.
3. Remediation Loop Node (Loop-in-Loop):
   - Iterates over actionable findings ONE BY ONE to isolate context and prevent LLM hallucination.
   - PydanticAI agent dynamically invokes containment tools (@agent.tool) and archives findings.
4. AI Notification Node:
   - Formats incident summary and delivers via AWS SES (Email), Slack, Discord, and Console.
"""

import sys
import logging
from typing import Optional, Dict, Any

from config import Config
from fetcher import FindingFetcher, FindingRuleEvaluator
from remediation_agent import GuardDutyRemediationAgent
from notifier import NotificationService

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger("IncidentResponseWorkflow")


def run_pipeline(finding_source_file: Optional[str] = None, fetch_live_aws: bool = False) -> Dict[str, Any]:
    config = Config()

    logger.info("=================================================================")
    logger.info("🛡️ Autonomous Cloud Incident Response: AWS GuardDuty Workflow")
    logger.info(f"Region: {config.aws_region} | Dry-Run Mode: {config.dry_run}")
    logger.info(f"AI Provider: {config.llm_provider.upper()} (PydanticAI)")
    logger.info("=================================================================")

    # ─────────────────────────────────────────────────────────────
    # NODE 1: Fetch GuardDuty Findings
    # ─────────────────────────────────────────────────────────────
    logger.info("▶ [Node 1: Fetch GuardDuty Findings] Starting ingestion...")
    fetcher = FindingFetcher(region=config.aws_region)
    findings = []

    if fetch_live_aws:
        findings = fetcher.fetch_from_aws(min_severity=1.0)
    elif finding_source_file:
        findings = fetcher.load_from_file(finding_source_file)
    else:
        findings = fetcher.load_from_file("sample_guardduty_finding.json")

    if not findings:
        logger.info("No findings retrieved from source. Workflow completed cleanly.")
        return {"status": "NO_FINDINGS_INGESTED", "total_findings": 0}

    logger.info(f"✔ [Node 1: Fetch GuardDuty Findings] Retrieved {len(findings)} raw finding(s).")

    # ─────────────────────────────────────────────────────────────
    # NODE 2: Rule Evaluator Node (Filter / Condition Gatekeeper)
    # ─────────────────────────────────────────────────────────────
    logger.info("▶ [Node 2: Rule Evaluator Gatekeeper] Filtering findings against rule set...")
    evaluator = FindingRuleEvaluator(min_severity=config.remediation_severity_threshold)
    eval_result = evaluator.evaluate(findings)

    # Rule Condition Branching:
    if not eval_result["condition_matched"]:
        logger.info("🛑 [Workflow Condition: FALSE] No findings matched the actionable rule set.")
        logger.info(f"   ↳ Reason: {eval_result['summary']}")
        logger.info("   ↳ Action: Terminating workflow cleanly. (No remediation required)")
        return {
            "status": "CONDITION_FALSE_TERMINATED",
            "condition_matched": False,
            "total_findings": len(findings),
            "summary": eval_result["summary"]
        }

    actionable_findings = eval_result["matching_findings"]
    logger.info(f"✅ [Workflow Condition: TRUE] {len(actionable_findings)} finding(s) matched criteria. Proceeding to Remediation Loop.")

    # ─────────────────────────────────────────────────────────────
    # NODE 3: Remediation Loop (Loop-in-Loop: Process Findings One-by-One)
    # ─────────────────────────────────────────────────────────────
    logger.info("▶ [Node 3: Remediation Loop Node] Entering Loop-in-Loop iterative execution...")
    agent = GuardDutyRemediationAgent(
        region=config.aws_region,
        dry_run=config.dry_run,
        llm_provider=config.llm_provider,
        bedrock_model_id=config.bedrock_model_id,
        anthropic_api_key=config.anthropic_api_key,
        anthropic_model_id=config.anthropic_model_id,
        openai_api_key=config.openai_api_key,
        openai_model_id=config.openai_model_id
    )

    # Process findings one by one in isolated turns to prevent AI context pollution
    results = agent.run_remediation_loop(actionable_findings)

    # ─────────────────────────────────────────────────────────────
    # NODE 4: AI Notification Dispatch via AWS SES
    # ─────────────────────────────────────────────────────────────
    logger.info("▶ [Node 4: AI Notification Node] Compiling incident report for user delivery...")
    notifier = NotificationService(
        slack_webhook=config.slack_webhook_url,
        discord_webhook=config.discord_webhook_url,
        ses_sender=config.ses_sender_email,
        ses_recipients=config.ses_recipient_emails,
        ses_region=config.ses_region,
        dry_run=config.dry_run
    )
    notifier.send_incident_report(results)

    logger.info("🎉 GuardDuty Autonomous Remediation Workflow completed successfully.")
    return {
        "status": "COMPLETED",
        "condition_matched": True,
        "actionable_count": len(actionable_findings),
        "remediation_results": results
    }


if __name__ == "__main__":
    file_arg = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else None
    run_pipeline(finding_source_file=file_arg)
