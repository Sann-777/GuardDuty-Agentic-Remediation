"""
test_agent.py - Automated Unit Tests
====================================
Tests the agent against sample findings to ensure decision logic and
tools remain bug-free.
"""

import json
from pathlib import Path
from fetcher import FindingRuleEvaluator
from remediation_agent import GuardDutyRemediationAgent
from llm_client import PydanticAIRemediationAgent, RemediationDecision


def test_agent_ssh_bruteforce_remediation():
    finding_path = Path(__file__).parent / "sample_guardduty_finding.json"
    with open(finding_path) as f:
        finding = json.load(f)

    agent = GuardDutyRemediationAgent(region="us-east-1", dry_run=True)
    report = agent.process_finding(finding)

    assert report["action_required"] == "remediation"
    assert report["source_ip"] == "185.220.101.5"
    assert report["reputation_confident_score"] >= 90
    assert report["finding_archived"] is True
    assert "NACL" in report["action_taken"]


def test_agent_benign_finding():
    finding_path = Path(__file__).parent / "sample_guardduty_finding.json"
    with open(finding_path) as f:
        finding = json.load(f)

    # Change finding to low severity informational
    finding["detail"]["type"] = "Policy:IAMUser/RootCredentialUsage"
    finding["detail"]["severity"] = 1.0
    finding["detail"]["service"]["action"]["networkConnectionAction"]["remoteIpDetails"]["ipAddressV4"] = "10.0.1.5"

    agent = GuardDutyRemediationAgent(region="us-east-1", dry_run=True)
    report = agent.process_finding(finding)

    assert report["action_required"] == "notify"
    assert report["finding_archived"] is False


def test_agent_batch_workflow():
    finding_path = Path(__file__).parent / "sample_guardduty_finding.json"
    with open(finding_path) as f:
        finding = json.load(f)

    agent = GuardDutyRemediationAgent(region="us-east-1", dry_run=True)
    batch_res = agent.run_full_workflow([finding])

    assert batch_res["status"] == "COMPLETED"
    assert batch_res["total_processed"] == 1
    assert batch_res["remediated_count"] == 1


def test_pydantic_ai_reasoning_agent():
    ai_engine = PydanticAIRemediationAgent(provider="test")
    decision = ai_engine.reason_over_finding(
        finding_context={"finding_type": "UnauthorizedAccess:EC2/SSHBruteForce", "severity": 8.0},
        threat_intel={"abuse_confidence_score": 95},
        available_tools=["block_nacl", "archive_finding"]
    )

    assert "action_required" in decision
    assert decision["action_required"] in ["remediation", "notify"]
    assert isinstance(decision["actions_to_execute"], list)
    assert len(decision["reasoning"]) > 0
    # Validate that it matches RemediationDecision schema
    validated = RemediationDecision.model_validate(decision)
    assert validated.action_required == decision["action_required"]


def test_rule_evaluator_condition_branching():
    evaluator = FindingRuleEvaluator(min_severity=7.0)

    # 1. Actionable finding -> Condition TRUE
    actionable = [{
        "detail": {
            "id": "f-1",
            "type": "UnauthorizedAccess:EC2/SSHBruteForce",
            "severity": 7.5,
            "service": {"archived": False}
        }
    }]
    eval_true = evaluator.evaluate(actionable)
    assert eval_true["condition_matched"] is True
    assert len(eval_true["matching_findings"]) == 1

    # 2. Low-severity finding -> Condition FALSE (Terminates workflow)
    benign = [{
        "detail": {
            "id": "f-2",
            "type": "Policy:IAMUser/RootCredentialUsage",
            "severity": 1.0,
            "service": {"archived": False}
        }
    }]
    eval_false = evaluator.evaluate(benign)
    assert eval_false["condition_matched"] is False
    assert len(eval_false["matching_findings"]) == 0
    assert eval_false["discarded_count"] == 1


def test_loop_in_loop_remediation():
    finding_path = Path(__file__).parent / "sample_guardduty_finding.json"
    with open(finding_path) as f:
        finding = json.load(f)

    agent = GuardDutyRemediationAgent(region="us-east-1", dry_run=True)
    loop_results = agent.run_remediation_loop([finding])

    assert len(loop_results) == 1
    assert loop_results[0]["action_required"] == "remediation"
    assert loop_results[0]["finding_archived"] is True


