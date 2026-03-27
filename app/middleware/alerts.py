import logging
import json
import os
from typing import Optional
import aiohttp

logger = logging.getLogger(__name__)

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
SLACK_ENABLED = bool(SLACK_WEBHOOK_URL)


async def send_slack_alert(
    title: str,
    severity: str,
    details: dict,
    user_id: Optional[str] = None
) -> bool:
    if not SLACK_ENABLED:
        logger.debug("Slack alerts disabled")
        return False

    color_map = {
        "CRITICAL": "#FF0000",
        "HIGH": "#FFA500",
        "MEDIUM": "#FFFF00",
        "LOW": "#00FF00"
    }
    color = color_map.get(severity, "#CCCCCC")

    payload = {
        "attachments": [
            {
                "fallback": title,
                "color": color,
                "title": title,
                "fields": [
                    {"title": "Severity", "value": severity, "short": True},
                    {"title": "User ID", "value": user_id or "unknown", "short": True},
                    {"title": "Details", "value": json.dumps(details, indent=2), "short": False},
                ]
            }
        ]
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(SLACK_WEBHOOK_URL, json=payload) as response:
                if response.status == 200:
                    logger.info(f"Slack alert sent: {title}")
                    return True
                else:
                    logger.error(f"Slack alert failed: {response.status}")
                    return False
    except Exception as e:
        logger.error(f"Slack alert exception: {e}")
        return False


async def alert_output_filter(user_id: str, pattern: str, original_reply: str) -> None:
    await send_slack_alert(
        title="🚨 CRITICAL: Output Filter Triggered",
        severity="CRITICAL",
        details={
            "pattern": pattern,
            "preview": original_reply[:200]
        },
        user_id=user_id
    )


async def alert_injection_blocked(user_id: str, injection_score: float, message_preview: str) -> None:
    await send_slack_alert(
        title="⚠️ HIGH: Injection Attack Blocked",
        severity="HIGH",
        details={
            "score": injection_score,
            "message": message_preview[:100]
        },
        user_id=user_id
    )