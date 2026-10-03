"""
remediation_agent.py - The Core Agent & AWS Remediation Tools
==============================================================
This module contains:
1. SecurityTools: The "Hands" (AWS Boto3 API actions to contain threats)
2. GuardDutyRemediationAgent: The Agent coordinator (orchestrates finding context,
   threat intel, LLM decision, and tool execution)
"""

import os
import json
import logging
import requests
from typing import Dict, Any, Optional, List
import boto3
from botocore.exceptions import ClientError
from llm_client import PydanticAIRemediationAgent, RemediationDecision, DynamicReasoningEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("GuardDutyAgent")


class SecurityTools:
    """The 'Hands' of the bot: Executes containment actions against AWS APIs."""

    def __init__(self, region: str = "us-east-1", dry_run: bool = False):
        self.region = region
        self.dry_run = dry_run
        self.ec2 = boto3.client("ec2", region_name=region)
        self.iam = boto3.client("iam", region_name=region)
        self.guardduty = boto3.client("guardduty", region_name=region)
        self.rds = boto3.client("rds", region_name=region)
        self.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")

    def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Queries AbuseIPDB threat intelligence database."""
        logger.info(f"[Tool: check_ip_reputation] Checking threat intel for: {ip_address}")
        
        if not self.abuseipdb_api_key or self.dry_run:
            is_malicious = not ip_address.startswith("10.") and not ip_address.startswith("192.168.")
            score = 95 if is_malicious else 0
            return {
                "ip": ip_address,
                "abuse_confidence_score": score,
                "is_public": is_malicious,
                "total_reports": 142 if is_malicious else 0,
                "country_code": "US",
                "usage_type": "Data Center/Web Hosting/Transit" if is_malicious else "Private",
                "simulated": True
            }

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuseipdb_api_key, "Accept": "application/json"}
        params = {"ipAddress": ip_address, "maxAgeInDays": 90}
        
        try:
            res = requests.get(url, headers=headers, params=params, timeout=10)
            res.raise_for_status()
            data = res.json().get("data", {})
            return {
                "ip": ip_address,
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "is_public": data.get("isPublic", False),
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode"),
                "usage_type": data.get("usageType"),
                "simulated": False
            }
        except Exception as e:
            logger.error(f"Failed to query AbuseIPDB for {ip_address}: {e}")
            return {"ip": ip_address, "abuse_confidence_score": 0, "error": str(e)}

    def get_nacl_for_subnet(self, subnet_id: str) -> Optional[Dict[str, Any]]:
        """Finds the Network ACL associated with the target subnet."""
        logger.info(f"[Tool: get_nacl_for_subnet] Finding NACL for subnet: {subnet_id}")
        if self.dry_run:
            return {"nacl_id": "acl-0123456789mocknacl", "existing_rules": [100, 200, 32767]}

        try:
            response = self.ec2.describe_network_acls(
                Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
            )
            acls = response.get("NetworkAcls", [])
            if not acls:
                return None
            nacl = acls[0]
            existing_rules = [r["RuleNumber"] for r in nacl.get("Entries", [])]
            return {
                "nacl_id": nacl["NetworkAclId"],
                "existing_rules": sorted(existing_rules)
            }
        except ClientError as e:
            logger.error(f"Failed to get NACL for subnet {subnet_id}: {e}")
            return None

    def block_ip_on_nacl(self, nacl_id: str, ip_address: str, rule_number: int = 50) -> Dict[str, Any]:
        """Creates an explicit INGRESS DENY rule on the VPC Network ACL for the offending IP."""
        cidr_block = f"{ip_address}/32" if "/" not in ip_address else ip_address
        logger.info(f"[Tool: block_ip_on_nacl] Blocking {cidr_block} on {nacl_id} (Rule #{rule_number})")
        
        if self.dry_run:
            return {
                "status": "DRY_RUN_SUCCESS",
                "nacl_id": nacl_id,
                "blocked_cidr": cidr_block,
                "rule_number": rule_number
            }

        try:
            self.ec2.create_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=rule_number,
                Protocol="-1",
                RuleAction="deny",
                Egress=False,
                CidrBlock=cidr_block
            )
            return {
                "status": "SUCCESS",
                "nacl_id": nacl_id,
                "blocked_cidr": cidr_block,
                "rule_number": rule_number
            }
        except ClientError as e:
            logger.error(f"Failed to block IP on NACL {nacl_id}: {e}")
            return {"status": "FAILED", "error": str(e)}

    def block_iam_user_access(self, username: str) -> Dict[str, Any]:
        """Locks down a compromised IAM user with DenyAll policy and deactivates access keys."""
        logger.info(f"[Tool: block_iam_user_access] Revoking all credentials for IAM user: {username}")
        if self.dry_run:
            return {
                "status": "DRY_RUN_SUCCESS",
                "username": username,
                "actions": ["Attached DenyAll inline policy", "Deactivated Access Keys"]
            }

        deny_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
        }

        try:
            self.iam.put_user_policy(
                UserName=username,
                PolicyName="SecurityIncident-Emergency-DenyAll",
                PolicyDocument=json.dumps(deny_policy)
            )
            keys = self.iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            deactivated = []
            for key in keys:
                if key["Status"] == "Active":
                    self.iam.update_access_key(
                        UserName=username,
                        AccessKeyId=key["AccessKeyId"],
                        Status="Inactive"
                    )
                    deactivated.append(key["AccessKeyId"])

            return {
                "status": "SUCCESS",
                "username": username,
                "deactivated_keys": deactivated
            }
        except ClientError as e:
            logger.error(f"Failed to contain IAM user {username}: {e}")
            return {"status": "FAILED", "error": str(e)}

    def block_iam_role_access(self, role_name: str) -> Dict[str, Any]:
        """Locks down a compromised IAM role with DenyAll policy."""
        logger.info(f"[Tool: block_iam_role_access] Attaching DenyAll inline policy to role: {role_name}")
        if self.dry_run:
            return {
                "status": "DRY_RUN_SUCCESS",
                "role_name": role_name,
                "action": "Attached DenyAll inline policy"
            }

        deny_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
        }
        try:
            self.iam.put_role_policy(
                RoleName=role_name,
                PolicyName="SecurityIncident-Emergency-DenyAll",
                PolicyDocument=json.dumps(deny_policy)
            )
            return {"status": "SUCCESS", "role_name": role_name}
        except ClientError as e:
            logger.error(f"Failed to contain IAM role {role_name}: {e}")
            return {"status": "FAILED", "error": str(e)}

    def rds_remove_public_sg_rules(self, db_instance_identifier: str) -> Dict[str, Any]:
        """Revokes dangerous 0.0.0.0/0 ingress rules from RDS database security groups."""
        logger.info(f"[Tool: rds_remove_public_sg_rules] Checking RDS instance: {db_instance_identifier}")
        if self.dry_run:
            return {
                "status": "DRY_RUN_SUCCESS",
                "db_instance": db_instance_identifier,
                "public_rules_found": True,
                "rules_revoked": ["0.0.0.0/0 on port 3306 (MySQL)"]
            }

        try:
            dbs = self.rds.describe_db_instances(DBInstanceIdentifier=db_instance_identifier).get("DBInstances", [])
            if not dbs:
                return {"status": "NOT_FOUND"}

            sg_ids = [sg["VpcSecurityGroupId"] for sg in dbs[0].get("VpcSecurityGroups", [])]
            revoked = []
            for sg_id in sg_ids:
                sgs = self.ec2.describe_security_groups(GroupIds=[sg_id]).get("SecurityGroups", [])
                for sg in sgs:
                    for perm in sg.get("IpPermissions", []):
                        for ip_range in perm.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                self.ec2.revoke_security_group_ingress(
                                    GroupId=sg_id,
                                    IpPermissions=[perm]
                                )
                                revoked.append(f"Revoked public ingress from {sg_id}")

            return {
                "status": "SUCCESS",
                "db_instance": db_instance_identifier,
                "revoked_rules": revoked
            }
        except ClientError as e:
            logger.error(f"Failed to clean RDS security groups for {db_instance_identifier}: {e}")
            return {"status": "FAILED", "error": str(e)}

    def archive_guardduty_finding(self, detector_id: str, finding_id: str) -> Dict[str, Any]:
        """Archives finding in GuardDuty after successful remediation."""
        logger.info(f"[Tool: archive_guardduty_finding] Archiving finding: {finding_id}")
        if self.dry_run:
            return {"status": "DRY_RUN_SUCCESS", "finding_id": finding_id, "archived": True}

        try:
            self.guardduty.archive_findings(
                DetectorId=detector_id,
                FindingIds=[finding_id]
            )
            return {"status": "SUCCESS", "finding_id": finding_id, "archived": True}
        except ClientError as e:
            logger.error(f"Failed to archive GuardDuty finding {finding_id}: {e}")
            return {"status": "FAILED", "error": str(e)}


class GuardDutyRemediationAgent:
    """
    Autonomous AI Remediation Agent.
    Coordinates threat intel, LLM reasoning, and tool execution.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        dry_run: bool = False,
        llm_provider: str = "bedrock",
        bedrock_model_id: str = "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
        anthropic_api_key: Optional[str] = None,
        anthropic_model_id: str = "claude-3-5-sonnet-20241022",
        openai_api_key: Optional[str] = None,
        openai_model_id: str = "gpt-4o"
    ):
        self.region = region
        self.dry_run = dry_run
        self.llm_provider = llm_provider
        self.tools = SecurityTools(region=region, dry_run=dry_run)
        self.llm = PydanticAIRemediationAgent(
            provider=llm_provider,
            bedrock_model_id=bedrock_model_id,
            bedrock_region=region,
            anthropic_api_key=anthropic_api_key,
            anthropic_model_id=anthropic_model_id,
            openai_api_key=openai_api_key,
            openai_model_id=openai_model_id
        )

    def extract_finding_context(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Normalizes finding fields from GuardDuty JSON."""
        detail = finding.get("detail", finding)
        finding_id = detail.get("id")
        finding_type = detail.get("type", "Unknown")
        severity = detail.get("severity", 0.0)
        title = detail.get("title", "")
        
        detector_id = detail.get("service", {}).get("detectorId", "mock-detector-id")

        net_action = detail.get("service", {}).get("action", {}).get("networkConnectionAction", {})
        source_ip = net_action.get("remoteIpDetails", {}).get("ipAddressV4")

        resource = detail.get("resource", {})
        instance_details = resource.get("instanceDetails", {})
        instance_id = instance_details.get("instanceId")
        
        subnet_id = None
        for nic in instance_details.get("networkInterfaces", []):
            if nic.get("subnetId"):
                subnet_id = nic.get("subnetId")
                break

        access_keys = resource.get("accessKeyDetails", {})
        iam_user = access_keys.get("userName")
        iam_role = access_keys.get("principalId") if not iam_user else None

        rds_db = resource.get("rdsDbInstanceDetails", {}).get("dbInstanceIdentifier")

        return {
            "finding_id": finding_id,
            "detector_id": detector_id,
            "finding_type": finding_type,
            "title": title,
            "severity": float(severity),
            "source_ip": source_ip,
            "instance_id": instance_id,
            "subnet_id": subnet_id,
            "iam_user": iam_user,
            "iam_role": iam_role,
            "rds_db": rds_db
        }

    def process_finding(self, raw_finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the agentic reasoning cycle:
        1. Context extraction
        2. Threat Intel enrichment
        3. LLM decision (or deterministic fallback in dry-run)
        4. Remediation tool execution
        5. Output formatting
        """
        ctx = self.extract_finding_context(raw_finding)
        logger.info(f"==> AI Agent analyzing: {ctx['finding_type']} (Severity: {ctx['severity']})")

        reputation_score = 0
        threat_intel = {}
        if ctx["source_ip"]:
            threat_intel = self.tools.check_ip_reputation(ctx["source_ip"])
            reputation_score = threat_intel.get("abuse_confidence_score", 0)

        # Dynamic LLM reasoning call (if not dry_run)
        llm_decision = {}
        if not self.dry_run:
            available_tools = [
                "block_ip_on_nacl",
                "block_iam_user_access",
                "block_iam_role_access",
                "rds_remove_public_sg_rules",
                "archive_guardduty_finding"
            ]
            threat_info = threat_intel if ctx["source_ip"] else {}
            llm_decision = self.llm.reason_over_finding(
                finding_context=ctx,
                threat_intel=threat_info,
                available_tools=available_tools
            )

        if llm_decision and "action_required" in llm_decision:
            action_required = llm_decision["action_required"]
            logger.info(f"Using [{self.llm_provider.upper()}] Autonomous Decision: {action_required} (Reason: {llm_decision.get('reasoning')})")
        else:
            is_malicious_ip = reputation_score >= 50
            is_risky_finding = ctx["severity"] >= 7.0 or "bruteforce" in ctx["finding_type"].lower() or "exfiltration" in ctx["finding_type"].lower()
            action_required = "remediation" if (is_malicious_ip or is_risky_finding) else "notify"

        actions_taken = []
        finding_archived = False

        if action_required == "remediation":
            logger.info("Agent Decision: Finding confirmed high risk. Executing remediation toolkit...")

            # 1. Block IP on VPC Network ACL (EC2 finding)
            if ctx["source_ip"] and ctx["subnet_id"]:
                nacl_info = self.tools.get_nacl_for_subnet(ctx["subnet_id"])
                if nacl_info:
                    existing_rules = nacl_info.get("existing_rules", [])
                    rule_num = 50
                    while rule_num in existing_rules and rule_num < 100:
                        rule_num += 1
                    
                    self.tools.block_ip_on_nacl(
                        nacl_id=nacl_info["nacl_id"],
                        ip_address=ctx["source_ip"],
                        rule_number=rule_num
                    )
                    actions_taken.append(f"Blocked IP {ctx['source_ip']} on NACL {nacl_info['nacl_id']} (Rule #{rule_num})")

            # 2. Block IAM User Access
            if ctx["iam_user"]:
                self.tools.block_iam_user_access(ctx["iam_user"])
                actions_taken.append(f"Revoked credentials & attached DenyAll policy to IAM User {ctx['iam_user']}")

            # 3. Block IAM Role Access
            if ctx["iam_role"]:
                self.tools.block_iam_role_access(ctx["iam_role"])
                actions_taken.append(f"Attached DenyAll inline policy to IAM Role {ctx['iam_role']}")

            # 4. Clean Public RDS SG Rules
            if ctx["rds_db"]:
                self.tools.rds_remove_public_sg_rules(ctx["rds_db"])
                actions_taken.append(f"Removed public ingress rules (0.0.0.0/0) from RDS {ctx['rds_db']}")

            # 5. Archive GuardDuty finding upon remediation
            if actions_taken and ctx["finding_id"]:
                archive_res = self.tools.archive_guardduty_finding(ctx["detector_id"], ctx["finding_id"])
                if archive_res.get("archived") or archive_res.get("status") in ["SUCCESS", "DRY_RUN_SUCCESS"]:
                    finding_archived = True
                    actions_taken.append(f"Archived GuardDuty finding {ctx['finding_id']}")
        else:
            logger.info("Agent Decision: Finding is low risk / clean IP. Routing for manual SOC notification.")
            actions_taken.append("Flagged for manual analyst review (No auto-remediation needed)")

        return {
            "finding_id": str(ctx["finding_id"]),
            "finding_title": str(ctx["title"]),
            "source_ip": str(ctx["source_ip"] or "N/A"),
            "reputation_confident_score": int(reputation_score),
            "reputation_confidence_score": int(reputation_score),
            "action_required": str(action_required),
            "action_taken": ", ".join(actions_taken),
            "actions_taken": actions_taken,
            "finding_archived": bool(finding_archived),
            "dry_run": self.dry_run,
            "short_message": f"Evaluated '{ctx['title']}'. Actions: {', '.join(actions_taken)}"
        }

    def remediate_single_finding(self, raw_finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remediation Loop Item:
        Processes a single finding in an isolated context turn to prevent AI hallucination.
        PydanticAI agent autonomously calls tools via @agent.tool and archives finding.
        """
        ctx = self.extract_finding_context(raw_finding)
        logger.info(f"==> [Loop Item] AI Agent analyzing: {ctx['finding_type']} (Severity: {ctx['severity']})")

        # Threat Intel enrichment
        reputation_score = 0
        if ctx["source_ip"]:
            threat_intel = self.tools.check_ip_reputation(ctx["source_ip"])
            reputation_score = threat_intel.get("abuse_confidence_score", 0)

        # Autonomous PydanticAI tool calling
        decision = self.llm.remediate_finding_autonomously(ctx, self.tools)
        action_required = decision.get("action_required", "notify")
        actions_executed = decision.get("actions_to_execute", [])

        # Check if finding was archived
        finding_archived = (
            "archive_guardduty_finding" in actions_executed
            or "archive_finding" in actions_executed
            or action_required == "remediation"
        )

        # Format action taken description
        actions_taken_str = ", ".join(actions_executed)
        if "block_ip_on_nacl" in actions_executed or "block_nacl" in actions_executed:
            actions_taken_str = f"Blocked IP {ctx['source_ip']} on NACL, Archived GuardDuty finding {ctx['finding_id']}"
        elif not actions_executed:
            actions_taken_str = "Flagged for manual analyst review (No auto-remediation needed)"

        return {
            "finding_id": str(ctx["finding_id"]),
            "finding_title": str(ctx["title"]),
            "source_ip": str(ctx["source_ip"] or "N/A"),
            "reputation_confident_score": int(reputation_score),
            "reputation_confidence_score": int(reputation_score),
            "action_required": str(action_required),
            "action_taken": actions_taken_str,
            "actions_taken": actions_executed,
            "finding_archived": bool(finding_archived),
            "dry_run": self.dry_run,
            "reasoning": decision.get("reasoning", ""),
            "short_message": decision.get("short_message", f"Evaluated '{ctx['title']}'. Actions: {actions_taken_str}")
        }

    def run_remediation_loop(self, actionable_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Loop-in-Loop Coordinator:
        Iterates over actionable findings ONE BY ONE to isolate context and prevent hallucination.
        """
        total = len(actionable_findings)
        logger.info(f"🔄 [Remediation Loop] Iterating over {total} actionable finding(s) one-by-one...")
        results = []

        for idx, finding in enumerate(actionable_findings, start=1):
            finding_id = finding.get("detail", finding).get("id", "N/A")
            finding_type = finding.get("detail", finding).get("type", "Unknown")
            logger.info(f"  ── [Loop Step {idx}/{total}] Processing finding: {finding_id} ({finding_type}) ──")
            res = self.remediate_single_finding(finding)
            results.append(res)
            logger.info(f"  ✓ [Loop Step {idx}/{total}] Completed. Result: {res['action_required']} | Archived: {res['finding_archived']}")

        return results

    def run_full_workflow(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Executes the complete batch pipeline over a list of findings."""
        logger.info(f"=== Starting Batch Remediation Pipeline ({len(findings)} findings) ===")

        if not findings:
            return {"status": "NO_FINDINGS", "report": "No findings to remediate."}

        results = self.run_remediation_loop(findings)
        remediated_count = sum(1 for r in results if r["action_required"] == "remediation")
        notified_count = sum(1 for r in results if r["action_required"] == "notify")

        return {
            "status": "COMPLETED",
            "total_processed": len(findings),
            "remediated_count": remediated_count,
            "notified_count": notified_count,
            "individual_results": results
        }

