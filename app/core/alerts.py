import httpx
import logging
from app.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

async def send_security_alert(event_type: str, severity: str, details: str):
    """Sends a critical alert to a webhook (Slack/Discord/Teams)."""
    if severity not in ["HIGH", "CRITICAL"]:
        return

    payload = {
        "text": f"🚨 *Vigilant Security Alert*\n*Type:* {event_type}\n*Severity:* {severity}\n*Details:* {details}"
    }
    
    # Replace with your actual webhook URL in .env
    webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    
    try:
        async with httpx.AsyncClient() as client:
            await client.post(webhook_url, json=payload)
    except Exception as e:
        logger.error(f"Failed to send security alert: {e}")