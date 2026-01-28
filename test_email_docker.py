import resend
import os
from dotenv import load_dotenv

load_dotenv()

RESEND_API_KEY = os.getenv("RESEND_API_KEY")
EMAIL_FROM = os.getenv("EMAIL_FROM")

resend.api_key = RESEND_API_KEY

def send_email(to_email: str, subject: str, html_content: str):
    params = {
        "from": EMAIL_FROM,
        "to": [to_email],
        "subject": subject,
        "html": html_content,
    }
    
    try:
        print(f"Trying to send email from {EMAIL_FROM} to {to_email}...")
        email = resend.Emails.send(params)
        return email
    except Exception as e:
        print(f"Failed to send email: {e}")
        return None

if __name__ == "__main__":
    result = send_email("utkrishtthakur1@gmail.com", "Test Subject", "<h1>Test</h1>")
    if result:
        print(f"Email sent successfully: {result}")
    else:
        print("Email sending failed.")
