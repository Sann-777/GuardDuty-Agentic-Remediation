"""
config.py - Central Configuration & Environment Settings
=========================================================
Reads environment variables (or .env file) into clean Python variables.
No hardcoded credentials.
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class Config:
    # AWS Region and Execution Mode
    aws_region: str = os.getenv("AWS_DEFAULT_REGION", os.getenv("AWS_REGION", "us-east-1"))
    dry_run: bool = os.getenv("DRY_RUN", "true").lower() in ("true", "1", "yes")

    # Threat Intelligence (AbuseIPDB)
    abuseipdb_api_key: Optional[str] = os.getenv("ABUSEIPDB_API_KEY")

    # Dynamic AI Provider: "bedrock", "anthropic", or "openai"
    llm_provider: str = os.getenv("LLM_PROVIDER", "bedrock").lower()

    # AWS Bedrock Settings
    bedrock_model_id: str = os.getenv("BEDROCK_MODEL_ID", "us.anthropic.claude-3-5-sonnet-20241022-v2:0")
    bedrock_region: str = os.getenv("BEDROCK_REGION", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))

    # Anthropic API Settings
    anthropic_api_key: Optional[str] = os.getenv("ANTHROPIC_API_KEY")
    anthropic_model_id: str = os.getenv("ANTHROPIC_MODEL_ID", "claude-3-5-sonnet-20241022")

    # OpenAI API Settings
    openai_api_key: Optional[str] = os.getenv("OPENAI_API_KEY")
    openai_model_id: str = os.getenv("OPENAI_MODEL_ID", "gpt-4o")

    # Notification Settings (Slack & Discord)
    slack_webhook_url: Optional[str] = os.getenv("SLACK_WEBHOOK_URL")
    discord_webhook_url: Optional[str] = os.getenv("DISCORD_WEBHOOK_URL")

    # Notification Settings (AWS SES Email)
    ses_sender_email: Optional[str] = os.getenv("SES_SENDER_EMAIL")
    ses_recipient_emails: Optional[str] = os.getenv("SES_RECIPIENT_EMAILS")
    ses_region: str = os.getenv("SES_REGION", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))

    # Security Thresholds
    remediation_severity_threshold: float = float(os.getenv("SEVERITY_THRESHOLD", "7.0"))
    abuse_confidence_threshold: int = int(os.getenv("ABUSE_THRESHOLD", "50"))
