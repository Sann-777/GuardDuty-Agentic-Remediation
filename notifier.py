"""
notifier.py - Multi-Channel Alert Dispatcher (Slack, Discord, AWS SES Email)
=============================================================================
This is the "Voice" of the bot. It formats structured incident reports
and delivers them to the right security channels.
"""

import os
import json
import logging
import requests
from typing import List, Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("Notifier")


class NotificationService:
    """Dispatches executive security summaries across Slack, Discord, AWS SES, and Console."""

    def __init__(
        self,
        slack_webhook: Optional[str] = None,
        discord_webhook: Optional[str] = None,
        ses_sender: Optional[str] = None,
        ses_recipients: Optional[str] = None,
        ses_region: str = "us-east-1",
        dry_run: bool = False
    ):
        self.slack_webhook = slack_webhook
        self.discord_webhook = discord_webhook
        self.ses_sender = ses_sender
        self.ses_recipients = [r.strip() for r in ses_recipients.split(",") if r.strip()] if ses_recipients else []
        self.ses_region = ses_region
        self.dry_run = dry_run
        self.ses_client = boto3.client("ses", region_name=ses_region) if (ses_sender and self.ses_recipients) else None

    def send_incident_report(self, results: List[Dict[str, Any]]) -> None:
        """Send formatted incident report across all configured channels."""
        if not results:
            logger.info("No incident results to dispatch.")
            return

        remediated = sum(1 for r in results if r.get("action_required") == "remediation")
        flagged = sum(1 for r in results if r.get("action_required") == "notify")
        total = len(results)

        # 1. Build Markdown & Text Summary
        lines = [
            f"*🚨 GuardDuty Autonomous AI Responder: Incident Summary*",
            f"• *Total Findings Analyzed:* {total}",
            f"• *Autonomous Remediations:* {remediated}",
            f"• *Flagged for SOC Review:* {flagged}",
            "\n*Action Details:*"
        ]

        for r in results:
            status_icon = "🛡️" if r.get("action_required") == "remediation" else "⚠️"
            lines.append(
                f"{status_icon} *{r.get('finding_title', 'Finding')}* (Abuse Score: {r.get('reputation_confident_score', 0)}%)\n"
                f"   ↳ Actions: `{r.get('action_taken', 'None')}`\n"
                f"   ↳ Archived: `{r.get('finding_archived', False)}`"
            )

        text_payload = "\n".join(lines)

        # 1. Print formatted Console Output
        print("\n" + "=" * 30 + " [ NOTIFICATION DISPATCH ] " + "=" * 30)
        print(text_payload)
        print("=" * 77 + "\n")

        # 2. Dispatch to Slack Webhook
        if self.slack_webhook:
            self._send_slack(text_payload, remediated)

        # 3. Dispatch to Discord Webhook
        if self.discord_webhook:
            self._send_discord(text_payload)

        # 4. Dispatch to AWS SES Email
        if self.ses_sender and self.ses_recipients:
            self._send_ses(results, remediated, flagged, total)

    def _send_slack(self, text: str, remediated_count: int) -> None:
        color = "#e01e5a" if remediated_count > 0 else "#2eb886"
        payload = {
            "attachments": [
                {
                    "color": color,
                    "text": text,
                    "footer": "AWS GuardDuty Autonomous AI Responder"
                }
            ]
        }
        try:
            res = requests.post(self.slack_webhook, json=payload, timeout=10)
            if res.status_code == 200:
                logger.info("✅ Slack alert successfully sent.")
            else:
                logger.warning(f"Slack webhook failed: {res.status_code} {res.text}")
        except Exception as e:
            logger.error(f"Error dispatching Slack alert: {e}")

    def _send_discord(self, text: str) -> None:
        payload = {"content": text}
        try:
            res = requests.post(self.discord_webhook, json=payload, timeout=10)
            if res.status_code in (200, 204):
                logger.info("✅ Discord alert successfully sent.")
            else:
                logger.warning(f"Discord webhook failed: {res.status_code} {res.text}")
        except Exception as e:
            logger.error(f"Error dispatching Discord alert: {e}")

    def _send_ses(self, results: List[Dict[str, Any]], remediated: int, flagged: int, total: int) -> None:
        """Formats and sends an executive HTML email report via AWS SES."""
        logger.info(f"[Notification: AWS SES] Sending incident email to {self.ses_recipients} from {self.ses_sender}...")

        subject = f"🛡️ [GuardDuty Incident Report] {remediated} Remediated / {total} Processed"
        
        table_rows = []
        for r in results:
            badge_color = "#e01e5a" if r.get("action_required") == "remediation" else "#ffae00"
            archived_badge = '<span style="color: green; font-weight: bold;">Archived</span>' if r.get("finding_archived") else '<span style="color: gray;">Not Archived</span>'
            table_rows.append(f"""
            <tr>
                <td style="padding: 10px; border-bottom: 1px solid #ddd;">{r.get('finding_title')}</td>
                <td style="padding: 10px; border-bottom: 1px solid #ddd;"><code>{r.get('source_ip', 'N/A')}</code></td>
                <td style="padding: 10px; border-bottom: 1px solid #ddd;"><b>{r.get('reputation_confident_score', 0)}%</b></td>
                <td style="padding: 10px; border-bottom: 1px solid #ddd;"><span style="background-color: {badge_color}; color: white; padding: 3px 8px; border-radius: 4px;">{r.get('action_required').upper()}</span></td>
                <td style="padding: 10px; border-bottom: 1px solid #ddd;">{r.get('action_taken')}</td>
                <td style="padding: 10px; border-bottom: 1px solid #ddd;">{archived_badge}</td>
            </tr>
            """)

        html_body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f4f7f9; margin: 0; padding: 20px; }}
                .container {{ background-color: #ffffff; border-radius: 8px; max-width: 800px; margin: auto; padding: 25px; }}
                .header {{ border-bottom: 2px solid #232f3e; padding-bottom: 15px; margin-bottom: 20px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; }}
                th {{ background-color: #232f3e; color: white; padding: 10px; text-align: left; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2 style="margin: 0; color: #232f3e;">🛡️ Autonomous GuardDuty Incident Response</h2>
                </div>
                <h3>Incident Breakdown</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Finding</th>
                            <th>Attacker IP</th>
                            <th>Abuse Score</th>
                            <th>Decision</th>
                            <th>Actions Executed</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(table_rows)}
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """

        if self.dry_run:
            logger.info("ℹ️ [DRY RUN] SES Email simulated (would have sent HTML report to recipients).")
            return

        try:
            self.ses_client.send_email(
                Source=self.ses_sender,
                Destination={"ToAddresses": self.ses_recipients},
                Message={
                    "Subject": {"Data": subject},
                    "Body": {
                        "Html": {"Data": html_body},
                        "Text": {"Data": f"GuardDuty Report: {remediated} remediated out of {total} findings."}
                    }
                }
            )
            logger.info(f"✅ AWS SES Incident Report successfully dispatched to {self.ses_recipients}.")
        except ClientError as e:
            logger.error(f"Failed to send SES email: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in SES dispatch: {e}")
