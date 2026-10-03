"""
fetcher.py - Ingests GuardDuty findings from AWS API or Local JSON
==================================================================
This is the "Eyes" of the bot. It retrieves finding JSON payloads so the
agent can analyze them.
"""

import json
import logging
from typing import List, Dict, Any
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
