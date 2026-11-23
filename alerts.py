"""Send the report to Telegram and/or email. A channel is used only if its settings exist.

Settings come from environment variables, or from a .env file next to check.py:
    TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
    SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASSWORD, ALERT_EMAIL_TO
"""

import json
import os
import smtplib
import urllib.request
from email.message import EmailMessage
from pathlib import Path


def load_env(path):
    """Minimal .env reader: KEY=value lines. Real environment variables win."""
    path = Path(path)
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def send_telegram(text, token, chat_id):
    body = json.dumps({"chat_id": chat_id, "text": text[:4000]}).encode()
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        if json.load(resp).get("ok") is not True:
            raise RuntimeError("Telegram API returned ok=false")


def send_email(text, host, port, user, password, to):
    msg = EmailMessage()
    msg["Subject"] = "Domain check: problems found"
    msg["From"] = user
    msg["To"] = to
    msg.set_content(text)
    with smtplib.SMTP(host, port, timeout=15) as s:
        s.starttls()
        s.login(user, password)
        s.send_message(msg)


def send_all(text):
    """Send to every configured channel. Returns the names of channels that worked.
    A failing channel is reported but never crashes the daily run."""
    e = os.environ.get
    sent = []
    if e("TELEGRAM_BOT_TOKEN") and e("TELEGRAM_CHAT_ID"):
        try:
            send_telegram(text, e("TELEGRAM_BOT_TOKEN"), e("TELEGRAM_CHAT_ID"))
            sent.append("telegram")
        except Exception as ex:
            print(f"Telegram alert failed: {ex}")
    if e("SMTP_HOST") and e("SMTP_USER") and e("SMTP_PASSWORD") and e("ALERT_EMAIL_TO"):
        try:
            send_email(text, e("SMTP_HOST"), int(e("SMTP_PORT", "587")), e("SMTP_USER"),
                       e("SMTP_PASSWORD"), e("ALERT_EMAIL_TO"))
            sent.append("email")
        except Exception as ex:
            print(f"Email alert failed: {ex}")
    return sent
