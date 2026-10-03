"""
fetcher.py - Ingests GuardDuty findings from AWS API or Local JSON & Rule Evaluator
==================================================================================
This is the "Eyes" and "Gatekeeper" of the bot:
1. FindingFetcher: Ingests raw finding JSON payloads from AWS GuardDuty or disk.
2. FindingRuleEvaluator: Rule Evaluator & Filter Node. Checks findings against
   rule set (severity threshold, archived status, threat category).
   - If condition == TRUE: proceeds to remediation loop.
   - If condition == FALSE: gracefully terminates workflow.
"""

import json
import logging
from typing import List, Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("Fetcher")


class FindingFetcher:
    """Connects to AWS GuardDuty or loads test files from disk."""

    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self.client = boto3.client("guardduty", region_name=region)

    def fetch_from_aws(self, min_severity: float = 4.0, max_results: int = 50) -> List[Dict[str, Any]]:
        """
        Polls AWS GuardDuty API for active, unarchived findings.
        """
        logger.info(f"Connecting to AWS GuardDuty in region {self.region}...")
        findings = []

        try:
            detectors = self.client.list_detectors().get("DetectorIds", [])
            if not detectors:
                logger.warning(f"No GuardDuty detectors found in region {self.region}.")
                return []

            detector_id = detectors[0]
            criteria = {
                "Criterion": {
                    "service.archived": {"Eq": ["false"]},
                    "severity": {"Gte": int(min_severity)}
                }
            }

            finding_ids = self.client.list_findings(
                DetectorId=detector_id,
                FindingCriteria=criteria,
                MaxResults=max_results
            ).get("FindingIds", [])

            if not finding_ids:
                logger.info("No active unarchived findings matched the criteria.")
                return []

            logger.info(f"Found {len(finding_ids)} matching findings. Fetching full details...")
            details = self.client.get_findings(DetectorId=detector_id, FindingIds=finding_ids)
            findings = details.get("Findings", [])
            
        except ClientError as e:
            logger.error(f"AWS GuardDuty API error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching findings: {e}")

        return findings

    @staticmethod
    def load_from_file(file_path: str) -> List[Dict[str, Any]]:
        """Loads findings from a local JSON file for testing or offline demonstration."""
        logger.info(f"Loading local finding file: {file_path}")
        with open(file_path, "r") as f:
            data = json.load(f)
        
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            return [data]
        return []


class FindingRuleEvaluator:
    """
    Rule Evaluator Node (Filter / Condition Gatekeeper).
    Filters findings according to the rule criteria:
    - Must be unarchived (service.archived != True)
    - Severity >= min_severity threshold (default: 7.0 High/Critical)
    - Belongs to an actionable security attack category
    """

    def __init__(
        self,
        min_severity: float = 7.0,
        allowed_categories: Optional[List[str]] = None
    ):
        self.min_severity = min_severity
        self.allowed_categories = allowed_categories or [
            "unauthorizedaccess",
            "recon",
            "trojan",
            "stealth",
            "exfiltration",
            "cryptocurrency",
            "privilegeescalation",
            "impact",
            "backdoor",
            "execution",
            "persistence",
            "defenseevasion",
            "credentialaccess",
            "discovery",
            "lateralmovement",
            "policy"
        ]

    def evaluate(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Evaluates findings against the rule set.
        Returns:
            {
                "condition_matched": bool,     # True if actionable findings found, False otherwise
                "matching_findings": list,     # Findings passing the filter
                "discarded_count": int,        # Findings filtered out
                "summary": str                 # Evaluator explanation
            }
        """
        logger.info(f"[Rule Evaluator Node] Evaluating {len(findings)} finding(s) (Severity Threshold: {self.min_severity})...")
        matching_findings = []
        discarded_count = 0

        for f in findings:
            detail = f.get("detail", f)
            severity = float(detail.get("severity", 0.0))
            is_archived = detail.get("service", {}).get("archived", False)
            finding_type = str(detail.get("type", "")).lower()

            # Rule 1: Exclude already archived findings
            if is_archived:
                logger.info(f"  ↳ Discarding {detail.get('id', 'unknown')}: Finding is already archived.")
                discarded_count += 1
                continue

            # Rule 2: Minimum severity check
            if severity < self.min_severity:
                logger.info(f"  ↳ Discarding {detail.get('id', 'unknown')}: Severity {severity} is below threshold {self.min_severity}.")
                discarded_count += 1
                continue

            # Rule 3: Category match
            category_match = any(cat in finding_type for cat in self.allowed_categories)
            if not category_match:
                logger.info(f"  ↳ Discarding {detail.get('id', 'unknown')}: Type '{finding_type}' not in actionable categories.")
                discarded_count += 1
                continue

            # Passed all rules
            logger.info(f"  ✅ Matched Rule: {detail.get('id', 'unknown')} | Type: {detail.get('type')} | Severity: {severity}")
            matching_findings.append(f)

        condition_matched = len(matching_findings) > 0
        summary = (
            f"Rule set matched {len(matching_findings)} actionable finding(s) (discarded {discarded_count})."
            if condition_matched
            else f"No findings matched the rule set (all {discarded_count} discarded)."
        )

        return {
            "condition_matched": condition_matched,
            "matching_findings": matching_findings,
            "discarded_count": discarded_count,
            "summary": summary
        }
