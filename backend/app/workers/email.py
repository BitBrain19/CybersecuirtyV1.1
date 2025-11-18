"""
Email worker for sending password reset and notification emails.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)


class EmailWorker:
    """Email sending service."""
    
    @staticmethod
    async def send_password_reset_email(
        user_email: str,
        user_name: str,
        reset_token: str,
        expiry_minutes: int = 60
    ) -> bool:
        """
        Send password reset email with secure token link.
        
        Args:
            user_email: User's email address
            user_name: User's name
            reset_token: Password reset token
            expiry_minutes: Token expiry time in minutes
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Construct reset URL
            reset_url = f"{settings.FRONTEND_URL}/auth/reset-password?token={reset_token}"
            
            # Create message
            message = MIMEMultipart("alternative")
            message["Subject"] = "Reset Your Password - SecurityAI"
            message["From"] = settings.SMTP_FROM_EMAIL
            message["To"] = user_email
            
            # Plain text version
            text_content = f"""
Hello {user_name},

We received a request to reset your password. Click the link below to reset it:

{reset_url}

This link will expire in {expiry_minutes} minutes.

If you didn't request this, you can safely ignore this email.

Best regards,
SecurityAI Team
"""
            
            # HTML version
            html_content = f"""
<html>
  <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; background-color: #f9fafb;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
      <div style="background-color: white; border-radius: 8px; padding: 32px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">
        <h2 style="margin-top: 0; color: #1f2937; font-size: 24px; font-weight: 600;">Reset Your Password</h2>
        
        <p style="color: #4b5563; font-size: 16px; line-height: 1.5;">
          Hello {user_name},
        </p>
        
        <p style="color: #4b5563; font-size: 16px; line-height: 1.5;">
          We received a request to reset your password. Click the button below to proceed:
        </p>
        
        <div style="text-align: center; margin: 32px 0;">
          <a href="{reset_url}" style="background-color: #0ea5e9; color: white; padding: 12px 32px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block; font-size: 16px;">
            Reset Password
          </a>
        </div>
        
        <p style="color: #6b7280; font-size: 14px; line-height: 1.5;">
          This link will expire in {expiry_minutes} minutes.
        </p>
        
        <p style="color: #6b7280; font-size: 14px; line-height: 1.5;">
          If you didn't request this, you can safely ignore this email.
        </p>
        
        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 24px 0;">
        
        <p style="color: #9ca3af; font-size: 12px; text-align: center;">
          SecurityAI Team
        </p>
      </div>
    </div>
  </body>
</html>
"""
            
            # Attach both versions
            part1 = MIMEText(text_content, "plain")
            part2 = MIMEText(html_content, "html")
            message.attach(part1)
            message.attach(part2)
            
            # Send email
            with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
                server.starttls()
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                server.sendmail(
                    settings.SMTP_FROM_EMAIL,
                    user_email,
                    message.as_string()
                )
            
            logger.info(f"Password reset email sent to {user_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send password reset email: {str(e)}")
            return False
    
    @staticmethod
    async def send_notification_email(
        user_email: str,
        user_name: str,
        notification_title: str,
        notification_message: str,
        notification_type: str,
        severity: str
    ) -> bool:
        """
        Send notification email.
        
        Args:
            user_email: User's email address
            user_name: User's name
            notification_title: Notification title
            notification_message: Notification message
            notification_type: Type of notification (threat, vulnerability, alert, etc.)
            severity: Severity level (critical, high, medium, low, info)
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Color coding based on severity
            severity_colors = {
                "critical": "#dc2626",
                "high": "#ea580c",
                "medium": "#eab308",
                "low": "#22c55e",
                "info": "#0ea5e9",
            }
            severity_color = severity_colors.get(severity, "#0ea5e9")
            
            # Create message
            message = MIMEMultipart("alternative")
            message["Subject"] = f"[{severity.upper()}] {notification_title} - SecurityAI"
            message["From"] = settings.SMTP_FROM_EMAIL
            message["To"] = user_email
            
            # Plain text version
            text_content = f"""
Hello {user_name},

{notification_title}
Severity: {severity.upper()}

{notification_message}

Check your SecurityAI dashboard for more details.

Best regards,
SecurityAI Team
"""
            
            # HTML version
            html_content = f"""
<html>
  <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; background-color: #f9fafb;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
      <div style="background-color: white; border-radius: 8px; padding: 32px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">
        <div style="padding: 12px; background-color: {severity_color}20; border-left: 4px solid {severity_color}; border-radius: 4px; margin-bottom: 24px;">
          <p style="margin: 0; color: {severity_color}; font-weight: 600;">
            {severity.upper()} - {notification_type.upper()}
          </p>
        </div>
        
        <h2 style="margin-top: 0; color: #1f2937; font-size: 24px; font-weight: 600;">{notification_title}</h2>
        
        <p style="color: #4b5563; font-size: 16px; line-height: 1.5;">
          {notification_message}
        </p>
        
        <div style="text-align: center; margin: 32px 0;">
          <a href="{settings.FRONTEND_URL}/dashboard" style="background-color: #0ea5e9; color: white; padding: 12px 32px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block; font-size: 16px;">
            View Dashboard
          </a>
        </div>
        
        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 24px 0;">
        
        <p style="color: #9ca3af; font-size: 12px; text-align: center;">
          SecurityAI Team
        </p>
      </div>
    </div>
  </body>
</html>
"""
            
            # Attach both versions
            part1 = MIMEText(text_content, "plain")
            part2 = MIMEText(html_content, "html")
            message.attach(part1)
            message.attach(part2)
            
            # Send email
            with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
                server.starttls()
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                server.sendmail(
                    settings.SMTP_FROM_EMAIL,
                    user_email,
                    message.as_string()
                )
            
            logger.info(f"Notification email sent to {user_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send notification email: {str(e)}")
            return False
