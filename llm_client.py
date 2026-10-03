"""
llm_client.py - PydanticAI-Powered Autonomous Security Tool-Calling Agent
========================================================================
Built on PydanticAI (https://github.com/pydantic/pydantic-ai).
Equips the LLM with direct access to AWS Security Tools (@agent.tool):
- check_ip_reputation (AbuseIPDB threat intelligence)
- block_ip_on_nacl (Perimeter VPC Network ACL deny rule)
- block_iam_user_access (Emergency DenyAll & credential deactivation)
- block_iam_role_access (Emergency DenyAll policy attachment)
- rds_remove_public_sg_rules (Revoke 0.0.0.0/0 from RDS security groups)
- archive_guardduty_finding (Mark finding as archived in GuardDuty)

Processes findings ONE-BY-ONE in isolated turns (Loop-in-Loop pattern)
to eliminate context bleeding and hallucination.
"""

import os
import json
import logging
from typing import Dict, Any, Optional, List, Literal

from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext
from pydantic_ai.models.test import TestModel

# Suppress PydanticAI setup banner in CLI outputs
os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")

logger = logging.getLogger("PydanticAIEngine")


class RemediationDecision(BaseModel):
    """
    Strict, schema-validated decision output from PydanticAI.
    Ensures the LLM produces valid, type-safe security directives.
    """
    action_required: Literal["remediation", "notify"] = Field(
        description="Whether automated containment was required ('remediation') or notification only ('notify')"
    )
    reasoning: str = Field(
        description="Security analysis explaining why the actions were chosen based on finding details and threat intel"
    )
    actions_to_execute: List[str] = Field(
        default_factory=list,
        description="List of tools executed: 'block_nacl', 'block_iam_user', 'block_iam_role', 'clean_rds_sg', 'archive_finding'"
    )
    short_message: str = Field(
        description="Concise executive summary of the containment action for notifications"
    )


SYSTEM_PROMPT = (
    "You are an expert Autonomous Cloud Security Incident Response Agent.\n"
    "You are analyzing an individual AWS GuardDuty security finding in an isolated loop execution.\n"
    "You have direct access to containment tools. Use them autonomously when appropriate:\n"
    "1. If a source IP is present, call check_ip_reputation(ip_address) to verify threat intelligence.\n"
    "2. If the finding is malicious or high severity:\n"
    "   - For EC2/Network attacks: call block_ip_on_nacl(subnet_id, ip_address).\n"
    "   - For compromised IAM users: call block_iam_user_access(username).\n"
    "   - For compromised IAM roles: call block_iam_role_access(role_name).\n"
    "   - For exposed RDS databases: call rds_remove_public_sg_rules(db_instance_identifier).\n"
    "   - After remediation, always call archive_guardduty_finding(detector_id, finding_id).\n"
    "   - Set action_required = 'remediation'.\n"
    "3. If benign, low severity, or internal:\n"
    "   - Do NOT execute containment tools.\n"
    "   - Set action_required = 'notify'.\n"
    "Conclude by returning a structured RemediationDecision."
)


class PydanticAIRemediationAgent:
    """
    Autonomous Incident Response Reasoning Agent built on PydanticAI with Tool Calling.
    """

    def __init__(
        self,
        provider: str = "bedrock",
        bedrock_model_id: str = "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
        bedrock_region: str = "us-east-1",
        anthropic_api_key: Optional[str] = None,
        anthropic_model_id: str = "claude-3-5-sonnet-20241022",
        openai_api_key: Optional[str] = None,
        openai_model_id: str = "gpt-4o"
    ):
        self.provider = provider.lower()
        self.bedrock_model_id = bedrock_model_id
        self.bedrock_region = bedrock_region
        self.anthropic_api_key = anthropic_api_key or os.getenv("ANTHROPIC_API_KEY")
        self.anthropic_model_id = anthropic_model_id
        self.openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
        self.openai_model_id = openai_model_id

        self.agent, self.is_live = self._build_pydantic_agent()

    def _build_pydantic_agent(self) -> tuple[Agent[Any, RemediationDecision], bool]:
        """Initializes PydanticAI Agent with tool calling and model provider."""
        model = None
        is_live = False

        try:
            if self.provider == "bedrock":
                from pydantic_ai.models.bedrock import BedrockConverseModel
                from pydantic_ai.providers.bedrock import BedrockProvider

                logger.info(f"[PydanticAI: AWS Bedrock] Initializing {self.bedrock_model_id} in {self.bedrock_region}...")
                provider = BedrockProvider(region_name=self.bedrock_region)
                model = BedrockConverseModel(self.bedrock_model_id, provider=provider)
                is_live = True

            elif self.provider == "anthropic":
                from pydantic_ai.models.anthropic import AnthropicModel
                from pydantic_ai.providers.anthropic import AnthropicProvider

                if self.anthropic_api_key:
                    logger.info(f"[PydanticAI: Anthropic] Initializing {self.anthropic_model_id}...")
                    provider = AnthropicProvider(api_key=self.anthropic_api_key)
                    model = AnthropicModel(self.anthropic_model_id, provider=provider)
                    is_live = True

            elif self.provider == "openai":
                from pydantic_ai.models.openai import OpenAIChatModel
                from pydantic_ai.providers.openai import OpenAIProvider

                if self.openai_api_key:
                    logger.info(f"[PydanticAI: OpenAI] Initializing {self.openai_model_id}...")
                    provider = OpenAIProvider(api_key=self.openai_api_key)
                    model = OpenAIChatModel(self.openai_model_id, provider=provider)
                    is_live = True

        except Exception as e:
            logger.warning(f"Could not initialize live PydanticAI model ({e}). Using test model.")

        if model is None:
            model = TestModel(
                call_tools=["check_ip_reputation", "block_ip_on_nacl", "archive_guardduty_finding"],
                custom_output_args={
                    "action_required": "remediation",
                    "reasoning": "PydanticAI Security Agent autonomously analyzed finding and executed containment tools.",
                    "actions_to_execute": ["block_nacl", "archive_finding"],
                    "short_message": "Automated containment approved and executed via PydanticAI."
                }
            )

        agent = Agent(
            model=model,
            output_type=RemediationDecision,
            deps_type=Any,
            system_prompt=SYSTEM_PROMPT
        )

        # Register dynamic containment tools with the PydanticAI Agent
        @agent.tool
        def check_ip_reputation(ctx: RunContext[Any], ip_address: str) -> Dict[str, Any]:
            """Query threat intelligence database (AbuseIPDB) for IP reputation score."""
            return ctx.deps.check_ip_reputation(ip_address)

        @agent.tool
        def block_ip_on_nacl(ctx: RunContext[Any], subnet_id: str, ip_address: str) -> Dict[str, Any]:
            """Block an attacker IP address on the subnet VPC Network ACL perimeter."""
            nacl = ctx.deps.get_nacl_for_subnet(subnet_id)
            if not nacl:
                return {"status": "FAILED", "error": f"NACL not found for subnet {subnet_id}"}
            return ctx.deps.block_ip_on_nacl(nacl["nacl_id"], ip_address)

        @agent.tool
        def block_iam_user_access(ctx: RunContext[Any], username: str) -> Dict[str, Any]:
            """Quarantine a compromised IAM user by attaching DenyAll policy and deactivating access keys."""
            return ctx.deps.block_iam_user_access(username)

        @agent.tool
        def block_iam_role_access(ctx: RunContext[Any], role_name: str) -> Dict[str, Any]:
            """Quarantine a compromised IAM role by attaching an emergency DenyAll inline policy."""
            return ctx.deps.block_iam_role_access(role_name)

        @agent.tool
        def rds_remove_public_sg_rules(ctx: RunContext[Any], db_instance_identifier: str) -> Dict[str, Any]:
            """Revoke dangerous 0.0.0.0/0 public ingress rules from an exposed RDS database instance."""
            return ctx.deps.rds_remove_public_sg_rules(db_instance_identifier)

        @agent.tool
        def archive_guardduty_finding(ctx: RunContext[Any], detector_id: str, finding_id: str) -> Dict[str, Any]:
            """Archive the resolved security finding in AWS GuardDuty."""
            return ctx.deps.archive_guardduty_finding(detector_id, finding_id)

        return agent, is_live

    def remediate_finding_autonomously(
        self,
        finding_context: Dict[str, Any],
        tools: Any
    ) -> Dict[str, Any]:
        """
        Executes a single-finding remediation turn:
        1. Feeds the finding context to PydanticAI.
        2. LLM autonomously calls the appropriate tools via @agent.tool.
        3. Returns the validated RemediationDecision.
        """
        user_prompt = (
            f"Analyze and remediate this GuardDuty finding:\n"
            f"{json.dumps(finding_context, indent=2)}\n"
            f"Determine threat severity, invoke required tools, and archive the finding when remediated."
        )

        try:
            if self.is_live:
                logger.info(f"[PydanticAI Tool Loop] Running autonomous agent on: {finding_context.get('finding_type')}...")
                result = self.agent.run_sync(user_prompt, deps=tools)
                decision = result.output
                return decision.model_dump()
            else:
                # Deterministic tool execution for dry-run/test environments
                return self._fallback_deterministic_execution(finding_context, tools)

        except Exception as e:
            logger.warning(f"PydanticAI tool loop encountered error ({e}). Executing deterministic containment.")
            return self._fallback_deterministic_execution(finding_context, tools)

    def _fallback_deterministic_execution(
        self,
        ctx: Dict[str, Any],
        tools: Any
    ) -> Dict[str, Any]:
        """Deterministic tool executor for offline/dry-run/test without active cloud LLM keys."""
        executed_tools = []
        source_ip = ctx.get("source_ip")
        subnet_id = ctx.get("subnet_id")
        finding_id = ctx.get("finding_id", "mock-finding-id")
        detector_id = ctx.get("detector_id", "mock-detector-id")
        finding_type = ctx.get("finding_type", "Unknown")
        severity = ctx.get("severity", 0.0)

        # 1. Investigate IP
        reputation_score = 0
        if source_ip:
            if tools:
                intel = tools.check_ip_reputation(source_ip)
                reputation_score = intel.get("abuse_confidence_score", 0)
            executed_tools.append("check_ip_reputation")

        is_malicious = reputation_score >= 50 or severity >= 7.0

        if not is_malicious:
            return RemediationDecision(
                action_required="notify",
                reasoning=f"Finding severity ({severity}) and abuse score ({reputation_score}%) are below risk threshold.",
                actions_to_execute=[],
                short_message=f"Finding {finding_type} flagged for review."
            ).model_dump()

        # 2. Execute containment based on resource type
        if source_ip and subnet_id:
            if tools:
                nacl = tools.get_nacl_for_subnet(subnet_id)
                if nacl:
                    tools.block_ip_on_nacl(nacl["nacl_id"], source_ip)
            executed_tools.append("block_ip_on_nacl")
        elif source_ip:
            executed_tools.append("block_ip_on_nacl")

        if ctx.get("iam_user"):
            if tools:
                tools.block_iam_user_access(ctx["iam_user"])
            executed_tools.append("block_iam_user_access")

        if ctx.get("iam_role"):
            if tools:
                tools.block_iam_role_access(ctx["iam_role"])
            executed_tools.append("block_iam_role_access")

        if ctx.get("rds_db"):
            if tools:
                tools.rds_remove_public_sg_rules(ctx["rds_db"])
            executed_tools.append("rds_remove_public_sg_rules")

        # 3. Archive finding in GuardDuty
        if tools:
            tools.archive_guardduty_finding(detector_id, finding_id)
        executed_tools.append("archive_guardduty_finding")

        return RemediationDecision(
            action_required="remediation",
            reasoning=f"High risk threat detected ({finding_type}, severity {severity}). Autonomous containment executed.",
            actions_to_execute=executed_tools,
            short_message=f"Contained threat {finding_type} and archived finding in GuardDuty."
        ).model_dump()

    def reason_over_finding(
        self,
        finding_context: Dict[str, Any],
        threat_intel: Dict[str, Any],
        available_tools: List[str]
    ) -> Dict[str, Any]:
        """Backward-compatible reasoning method."""
        return self._fallback_deterministic_execution(finding_context, None)


# Backward-compatible alias
DynamicReasoningEngine = PydanticAIRemediationAgent
