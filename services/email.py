import resend
from config import settings

resend.api_key = settings.RESEND_API_KEY

def send_email(to_email: str, subject: str, html_content: str):
    """
    Base function to send email via Resend
    """
    params = {
        "from": settings.EMAIL_FROM,
        "to": [to_email],
        "subject": subject,
        "html": html_content,
    }
    
    try:
        email = resend.Emails.send(params)
        return email
    except Exception as e:
        # In production, use proper logging
        print(f"Failed to send email: {e}")
        return None
