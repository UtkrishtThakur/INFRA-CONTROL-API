from services.email import send_email

def send_verification_email(email: str, verification_link: str):
    """
    Sends a verification email to the user.
    """
    subject = "Verify your email - Infra Control"
    html_content = f"""
    <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
        <h2 style="color: #333;">Welcome to Infra!</h2>
        <p>Please click the button below to verify your email address and activate your account.</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{verification_link}" 
               style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                Verify Email
            </a>
        </div>
        <p style="color: #666; font-size: 14px;">
            If the button doesn't work, copy and paste this link into your browser: <br>
            <a href="{verification_link}">{verification_link}</a>
        </p>
        <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="color: #999; font-size: 12px;">This link will expire in 30 minutes. If you didn't create an account, you can safely ignore this email.</p>
    </div>
    """
    return send_email(email, subject, html_content)
