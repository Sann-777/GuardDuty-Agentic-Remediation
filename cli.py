#!/usr/bin/env python3
"""
cli.py - Interactive Terminal Interface
========================================
Run the bot from your terminal with customized flags:
  --dry-run / --live
  --aws
  --llm bedrock | anthropic | openai
  --slack-webhook
  --ses-sender / --ses-recipients
"""

import os
import sys
import argparse
from main import run_pipeline


def main():
    parser = argparse.ArgumentParser(
        description="Autonomous AI Agent for Amazon GuardDuty Incident Response & Remediation"
    )
    parser.add_argument(
        "--finding",
        "-f",
        default="sample_guardduty_finding.json",
        help="Path to local finding JSON file (default: sample_guardduty_finding.json)"
    )
    parser.add_argument(
        "--aws",
        action="store_true",
        help="Fetch active live findings directly from AWS GuardDuty instead of a local file"
    )
    parser.add_argument(
        "--region",
        "-r",
        default="us-east-1",
        help="AWS region (default: us-east-1)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Simulate remediation actions safely without making real AWS API changes (default: True)"
    )
    parser.add_argument(
        "--live",
        dest="dry_run",
        action="store_false",
        help="Execute real remediation changes against your AWS account"
    )
    parser.add_argument(
        "--llm",
        choices=["bedrock", "anthropic", "openai"],
        default="bedrock",
        help="Dynamic LLM provider (default: bedrock)"
    )
    parser.add_argument(
        "--slack-webhook",
        help="Slack incoming webhook URL to post incident summary"
    )
    parser.add_argument(
        "--ses-sender",
        help="AWS SES verified sender email address"
    )
    parser.add_argument(
        "--ses-recipients",
        help="Comma-separated recipient email addresses for SES report"
    )

    args = parser.parse_args()

    os.environ["AWS_DEFAULT_REGION"] = args.region
    os.environ["DRY_RUN"] = str(args.dry_run).lower()
    os.environ["LLM_PROVIDER"] = args.llm
    if args.slack_webhook:
        os.environ["SLACK_WEBHOOK_URL"] = args.slack_webhook
    if args.ses_sender:
        os.environ["SES_SENDER_EMAIL"] = args.ses_sender
    if args.ses_recipients:
        os.environ["SES_RECIPIENT_EMAILS"] = args.ses_recipients

    run_pipeline(
        finding_source_file=args.finding if not args.aws else None,
        fetch_live_aws=args.aws
    )


if __name__ == "__main__":
    main()
