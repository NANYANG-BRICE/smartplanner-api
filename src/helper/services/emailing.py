from email.message import EmailMessage
import smtplib
from fastapi import HTTPException
import logging
from helper.config.settings import Settings

app_settings = Settings()
logger = logging.getLogger(__name__)

class EmailService:
    @staticmethod
    def send_otp_email(email: str, otp_code: str, expiry_minutes: int, lang: str = "fr"):
        """Send OTP email in selected language (default: French)."""
        subject, text_body, html_body = EmailService._generate_otp_template(otp_code, expiry_minutes, lang)
        EmailService._send_email(email, subject, text_body, html_body)

    @staticmethod
    def send_new_password_email(email: str, new_password: str, lang: str = "fr"):
        """Send new password email in selected language (default: French)."""
        subject, text_body, html_body = EmailService._generate_new_password_template(new_password, lang)
        EmailService._send_email(email, subject, text_body, html_body)

    @staticmethod
    def send_password_reset_email(email: str, reset_link: str, lang: str = "fr"):
        """Send password reset email in selected language (default: French)."""
        subject, text_body, html_body = EmailService._generate_password_reset_template(reset_link, lang)
        EmailService._send_email(email, subject, text_body, html_body)

    @staticmethod
    def _generate_otp_template(otp_code: str, expiry_minutes: int, lang: str):
        """Generate OTP email content based on the language."""
        if lang == "en":
            subject = "Your OTP Code"
            text_body = (
                f"Hello,\n\n"
                f"Your OTP code is: {otp_code}\n"
                f"It will expire in {expiry_minutes} minutes.\n\n"
                f"Thank you,\n{app_settings.EMAIL_FROM_NAME} Team"
            )
            html_body = (
                f"<html><body>"
                f"<p>Hello,</p>"
                f"<p>Your OTP code is: <strong>{otp_code}</strong></p>"
                f"<p>It will expire in <strong>{expiry_minutes}</strong> minutes.</p>"
                f"<p>Thank you,<br/>The <b>{app_settings.EMAIL_FROM_NAME}</b> team</p>"
                f"</body></html>"
            )
        else:
            # Default to French
            subject = "Votre code OTP"
            text_body = (
                f"Bonjour,\n\n"
                f"Votre code OTP est : {otp_code}\n"
                f"Il expirera dans {expiry_minutes} minutes.\n\n"
                f"Merci,\nL'équipe {app_settings.EMAIL_FROM_NAME}"
            )
            html_body = (
                f"<html><body>"
                f"<p>Bonjour,</p>"
                f"<p>Votre code OTP est : <strong>{otp_code}</strong></p>"
                f"<p>Il expirera dans <strong>{expiry_minutes}</strong> minutes.</p>"
                f"<p>Merci,<br/>L'équipe <b>{app_settings.EMAIL_FROM_NAME}</b></p>"
                f"</body></html>"
            )

        return subject, text_body, html_body

    @staticmethod
    def _generate_new_password_template(new_password: str, lang: str):
        """Generate new password email content based on the language."""
        if lang == "en":
            subject = "Your New Password"
            text_body = (
                f"Hello,\n\n"
                f"Here is your new password: {new_password}\n"
                "For security reasons, we recommend that you change it upon your next login.\n\n"
                f"Thank you,\n{app_settings.EMAIL_FROM_NAME} Team"
            )
            html_body = (
                f"<html><body>"
                f"<p>Hello,</p>"
                f"<p>Here is your new password: <strong>{new_password}</strong></p>"
                f"<p>For security reasons, we recommend that you change it upon your next login.</p>"
                f"<p>Thank you,<br/>The <b>{app_settings.EMAIL_FROM_NAME}</b> team</p>"
                f"</body></html>"
            )
        else:
            # Default to French
            subject = "Votre nouveau mot de passe"
            text_body = (
                f"Bonjour,\n\n"
                f"Voici votre nouveau mot de passe : {new_password}\n"
                "Pour des raisons de sécurité, nous vous conseillons de le changer dès votre prochaine connexion.\n\n"
                f"Merci,\nL'équipe {app_settings.EMAIL_FROM_NAME}"
            )
            html_body = (
                f"<html><body>"
                f"<p>Bonjour,</p>"
                f"<p>Voici votre nouveau mot de passe : <strong>{new_password}</strong></p>"
                f"<p>Pour des raisons de sécurité, nous vous conseillons de le changer dès votre prochaine connexion.</p>"
                f"<p>Merci,<br/>L'équipe <b>{app_settings.EMAIL_FROM_NAME}</b></p>"
                f"</body></html>"
            )

        return subject, text_body, html_body

    @staticmethod
    def _generate_password_reset_template(reset_link: str, lang: str):
        """Generate password reset email content based on the language."""
        if lang == "en":
            subject = "Password Reset"
            text_body = (
                f"Hello,\n\n"
                f"To reset your password, please click on the following link:\n{reset_link}\n\n"
                "This link will expire in 30 minutes.\n\n"
                f"Thank you,\n{app_settings.EMAIL_FROM_NAME} Team"
            )
            html_body = (
                f"<html><body>"
                f"<p>Hello,</p>"
                f"<p>To reset your password, please click on the following link:</p>"
                f"<p><a href='{reset_link}'>{reset_link}</a></p>"
                f"<p>This link will expire in 30 minutes.</p>"
                f"<p>Thank you,<br/>The <b>{app_settings.EMAIL_FROM_NAME}</b> team</p>"
                f"</body></html>"
            )
        else:
            # Default to French
            subject = "Réinitialisation de votre mot de passe"
            text_body = (
                f"Bonjour,\n\n"
                f"Pour réinitialiser votre mot de passe, veuillez cliquer sur le lien suivant :\n{reset_link}\n\n"
                "Ce lien expirera dans 30 minutes.\n\n"
                f"Merci,\nL'équipe {app_settings.EMAIL_FROM_NAME}"
            )
            html_body = (
                f"<html><body>"
                f"<p>Bonjour,</p>"
                f"<p>Pour réinitialiser votre mot de passe, veuillez cliquer sur le lien suivant :</p>"
                f"<p><a href='{reset_link}'>{reset_link}</a></p>"
                f"<p>Ce lien expirera dans 30 minutes.</p>"
                f"<p>Merci,<br/>L'équipe <b>{app_settings.EMAIL_FROM_NAME}</b></p>"
                f"</body></html>"
            )

        return subject, text_body, html_body

    @staticmethod
    def _send_email(email: str, subject: str, text_body: str, html_body: str):
        """Send a secure email with both text and HTML content."""
        if not all([app_settings.SMTP_SERVER, app_settings.SMTP_PORT, app_settings.EMAIL_FROM_ADDRESS, app_settings.SMTP_PASSWORD]):
            logger.error("❌ Incomplete SMTP configuration.")
            raise HTTPException(status_code=500, detail="Invalid SMTP configuration")

        # Create the message
        message = EmailMessage()
        message["From"] = f"{app_settings.EMAIL_FROM_NAME} <{app_settings.EMAIL_FROM_ADDRESS}>"
        message["To"] = email
        message["Subject"] = subject
        message.set_content(text_body)
        message.add_alternative(html_body, subtype="html")

        # Send the email
        try:
            with smtplib.SMTP_SSL(app_settings.SMTP_SERVER, app_settings.SMTP_PORT) as smtp:
                smtp.login(app_settings.EMAIL_FROM_ADDRESS, app_settings.SMTP_PASSWORD)
                smtp.send_message(message)
                logger.info(f"✅ Email sent to {email} with subject: {subject}")
        except smtplib.SMTPAuthenticationError:
            logger.error("❌ SMTP Authentication failed.")
            raise HTTPException(status_code=500, detail="SMTP Authentication error")
        except smtplib.SMTPConnectError:
            logger.error(f"❌ Failed to connect to SMTP server: {app_settings.SMTP_SERVER}")
            raise HTTPException(status_code=500, detail="Failed to connect to SMTP server")
        except Exception as e:
            logger.error(f"❌ Error while sending email to {email}: {str(e)}")
            raise HTTPException(status_code=500, detail="Error while sending email")
