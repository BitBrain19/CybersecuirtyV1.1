"""
Enhanced Authentication endpoints with password reset functionality.
"""

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from pydantic import BaseModel, EmailStr, Field
import logging

from app.core.auth import get_current_user, create_access_token, verify_password, get_password_hash
from app.core.config import settings
from app.models.user import User
from app.models.password_reset_token import PasswordResetToken
from app.db.session import get_db
from app.workers.email import EmailWorker

logger = logging.getLogger(__name__)
router = APIRouter()


class LoginRequest(BaseModel):
    """Login request schema."""
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    """Login response schema."""
    access_token: str
    token_type: str = "bearer"
    user: dict


class RegisterRequest(BaseModel):
    """Register request schema."""
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str = Field(..., min_length=2)


class ForgotPasswordRequest(BaseModel):
    """Forgot password request schema."""
    email: EmailStr


class ForgotPasswordResponse(BaseModel):
    """Forgot password response schema."""
    success: bool
    message: str
    expires_in: int


class ResetPasswordRequest(BaseModel):
    """Reset password request schema."""
    token: str
    password: str = Field(..., min_length=8)
    password_confirm: str = Field(..., min_length=8)
    
    def validate(self):
        """Validate password reset request."""
        if self.password != self.password_confirm:
            raise ValueError("Passwords do not match")
        return True


class ResetPasswordResponse(BaseModel):
    """Reset password response schema."""
    success: bool
    message: str


class ValidateTokenRequest(BaseModel):
    """Validate token request schema."""
    token: str


class ValidateTokenResponse(BaseModel):
    """Validate token response schema."""
    valid: bool
    expires_at: datetime
    email: str


@router.post("/forgot-password", response_model=ForgotPasswordResponse)
async def forgot_password(
    request: ForgotPasswordRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Request password reset.
    
    Generates a secure token and sends password reset email to user.
    Rate limited to prevent abuse.
    """
    # Find user by email
    user = db.query(User).filter(User.email == request.email).first()
    
    if not user:
        # Don't reveal if email exists (security best practice)
        return ForgotPasswordResponse(
            success=True,
            message="If an account exists with this email, a reset link will be sent shortly.",
            expires_in=settings.PASSWORD_RESET_TOKEN_EXPIRY_MINUTES * 60,
        )
    
    # Invalidate any existing tokens
    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.used_at == None,
    ).update({PasswordResetToken.used_at: datetime.utcnow()})
    
    # Create new token
    reset_token = PasswordResetToken.create(
        user_id=user.id,
        expiry_minutes=settings.PASSWORD_RESET_TOKEN_EXPIRY_MINUTES,
    )
    db.add(reset_token)
    db.commit()
    
    # Send email in background
    background_tasks.add_task(
        EmailWorker.send_password_reset_email,
        user_email=user.email,
        user_name=user.full_name or user.email,
        reset_token=reset_token.token,
        expiry_minutes=settings.PASSWORD_RESET_TOKEN_EXPIRY_MINUTES,
    )
    
    logger.info(f"Password reset requested for user {user.id}")
    
    return ForgotPasswordResponse(
        success=True,
        message="If an account exists with this email, a reset link will be sent shortly.",
        expires_in=settings.PASSWORD_RESET_TOKEN_EXPIRY_MINUTES * 60,
    )


@router.post("/reset-password", response_model=ResetPasswordResponse)
async def reset_password(
    request: ResetPasswordRequest,
    db: Session = Depends(get_db),
):
    """
    Reset password using token.
    
    Token must be valid and not yet used.
    """
    # Validate passwords match
    try:
        request.validate()
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    
    # Find and validate token
    token_record = db.query(PasswordResetToken).filter(
        PasswordResetToken.token == request.token
    ).first()
    
    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid reset token"
        )
    
    # Check token validity
    if not token_record.is_valid():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token has expired or already been used"
        )
    
    # Get user
    user = db.query(User).filter(User.id == token_record.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Update password
    user.hashed_password = get_password_hash(request.password)
    token_record.mark_as_used()
    
    db.commit()
    
    logger.info(f"Password reset successful for user {user.id}")
    
    return ResetPasswordResponse(
        success=True,
        message="Password has been reset successfully. You can now log in with your new password."
    )


@router.get("/validate-token", response_model=ValidateTokenResponse)
async def validate_token(
    token: str,
    db: Session = Depends(get_db),
):
    """
    Validate password reset token.
    
    Returns token validity and expiry time if valid.
    """
    token_record = db.query(PasswordResetToken).filter(
        PasswordResetToken.token == token
    ).first()
    
    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid reset token"
        )
    
    if not token_record.is_valid():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token has expired or already been used"
        )
    
    # Get user email
    user = db.query(User).filter(User.id == token_record.user_id).first()
    
    return ValidateTokenResponse(
        valid=True,
        expires_at=token_record.expires_at,
        email=user.email if user else "unknown",
    )


@router.post("/login", response_model=LoginResponse)
async def login(
    credentials: LoginRequest,
    db: Session = Depends(get_db),
):
    """
    Login with email and password.
    
    Returns JWT access token.
    """
    # Find user
    user = db.query(User).filter(User.email == credentials.email).first()
    
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )
    
    # Create access token
    access_token = create_access_token(
        data={"sub": user.email, "user_id": str(user.id)}
    )
    
    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        user={
            "id": str(user.id),
            "email": user.email,
            "full_name": user.full_name,
            "is_admin": user.is_admin,
        }
    )


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(current_user: User = Depends(get_current_user)):
    """
    Logout user.
    
    In a stateless JWT-based system, logout is a client-side operation.
    This endpoint is primarily for logging/audit purposes.
    """
    logger.info(f"User {current_user.id} logged out")
    return {"success": True, "message": "Successfully logged out"}
