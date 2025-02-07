# src/auth/emails.py

# Standard library imports
import smtplib
from email.mime.image import MIMEImage
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

# FastAPI imports
from fastapi.responses import JSONResponse

# Local application imports
from src.config import settings


# Fix the template path to point inside `src/templates/`
BASE_DIR = Path(__file__).resolve().parent.parent.parent  # Go up 3 levels
TEMPLATES_DIR = BASE_DIR / "templates"  # Now points to `fastapi-auth/templates`
LOGO_FILE = "logo.png"
LOGO_PATH = BASE_DIR / "assets" / LOGO_FILE


# *********** ========== Email Sending Utility ========== ***********
def send_email(to_email: str, subject: str, template_name: str, context: dict, attachments=None):
    """
    Send an email with an HTML template.

    Args:
        to_email (str): Recipient's email address.
        subject (str): Email subject.
        template_name (str): The HTML template file name.
        context (dict): Dictionary with variables to render inside the email.
    """
    try:
        # Load HTML template
        template_path = TEMPLATES_DIR / template_name
        if not template_path.exists():
            raise FileNotFoundError(f"Email template {template_name} not found")

        html_content = template_path.read_text()

        # Replace placeholders in HTML template
        for key, value in context.items():
            html_content = html_content.replace(f"{{{{ {key} }}}}", str(value))

        # Create email message
        msg = MIMEMultipart()
        msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(html_content, "html"))

        # Add attachments if available
        if attachments:
            print(f"📎 Adding {len(attachments)} attachments...")
            for attachment in attachments:
                msg.attach(attachment)

        # Establish SMTP connection
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.ehlo()

            # Secure connection using TLS if enabled
            if settings.SMTP_USE_TLS:
                server.starttls()
                server.ehlo()  # Important: Re-establish EHLO after starttls()

            # Login to the SMTP server
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)

            # Send the email
            server.sendmail(settings.SMTP_FROM_EMAIL, to_email, msg.as_string())
        
        return True  # Indicate success

    except smtplib.SMTPException as e:
        return JSONResponse(
            status_code=500,
            content={"status": "error", 
                    "message": "Failed to send email due to SMTP error.", 
                    "error": str(e)}
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"status": "error", 
                    "message": "An unexpected error occurred while sending email.", 
                    "error": str(e)}
        )
# *********** ========== End of Email Sending Utility ========== ***********


# *********** ========== Registration Email Utility ========== ***********
def send_registration_email(user_email: str, user_name: str):
    """
    Send a welcome email after user registration, embedding the logo.
    """
    print(f"Attempting to send email to: {user_email}")  # Debugging log

    # Path to the embedded logo
    logo_path = LOGO_PATH
    logo_cid = "logo"  # Content ID for embedding

    # Read the logo image if it exists
    attachments = []
    if logo_path.exists():
        with open(logo_path, "rb") as logo_file:
            logo_data = logo_file.read()
            image = MIMEImage(logo_data)
            image.add_header("Content-ID", f"<{logo_cid}>")  # Reference in HTML
            image.add_header("Content-Disposition", "inline", filename=LOGO_FILE)
            attachments.append(image)  # Add to the attachments list
    else:
        print(f"⚠️ Warning: Logo not found at {logo_path}")  # Debugging log

    print(f"Email attachments: {attachments}")  # Debugging log
    
    try:
        send_email(
            to_email=user_email,
            subject="Welcome to Our Platform!",
            template_name="registration_email.html",
            context={
                "user_name": user_name,
                "current_year": datetime.now().year,
                "logo_cid": logo_cid,
            },
            attachments=attachments
        )
        print("✅ Email sending function executed without error.")
    except Exception as e:
        print(f"❌ Error inside send_email(): {str(e)}")
# *********** ========== End of Registration Email Utility ========== ***********


# *********** ========== Password Reset Email Utility ========== ***********
def send_password_reset_email(user_email: str, user_name: str, otp: str):
    """
    Send a password reset email, embedding the logo.
    """
    print(f"Attempting to send password reset email to: {user_email}")  # Debugging log

    # Path to the embedded logo
    logo_path = LOGO_PATH
    logo_cid = "logo"  # Content ID for embedding

    # Read the logo image if it exists
    attachments = []
    if logo_path.exists():
        with open(logo_path, "rb") as logo_file:
            logo_data = logo_file.read()
            image = MIMEImage(logo_data)
            image.add_header("Content-ID", f"<{logo_cid}>")  # Reference in HTML
            image.add_header("Content-Disposition", "inline", filename=LOGO_FILE)
            attachments.append(image)  # Add to the attachments list
    else:
        print(f"⚠️ Warning: Logo not found at {logo_path}")  # Debugging log

    print(f"Email attachments: {attachments}")  # Debugging log
    
    try:
        send_email(
            to_email=user_email,
            subject="Reset Your Password",
            template_name="password_reset_email.html",
            context={
                "user_name": user_name,
                "otp": otp,
                "current_year": datetime.now().year,
                "logo_cid": logo_cid,
            },
            attachments=attachments
        )
        print("✅ Password reset email sent successfully.")
    except Exception as e:
        print(f"❌ Error inside send_email(): {str(e)}")
# *********** ========== End of Password Reset Email Utility ========== ***********