"""Optional notification helper; does not send unless explicitly configured."""
import os
import smtplib
from email.mime.text import MIMEText

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")

class SecurityError(RuntimeError): pass

def send_notification(to_email, subject, body, html_body=None):
    if not to_email or "@" not in to_email: raise ValueError("Invalid recipient email address")
    if not SMTP_HOST or not SMTP_USER: raise SecurityError("SMTP is not configured")
    message = MIMEText(html_body or body, "html" if html_body else "plain", "utf-8")
    message["Subject"], message["From"], message["To"] = subject, SMTP_USER, to_email
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
        server.starttls(); server.login(SMTP_USER, SMTP_PASS); server.send_message(message)
    return True

def send_task_notification(to_email, task_title, task_url):
    return send_notification(to_email, f"Task completed: {task_title}", f"Details: {task_url}")
