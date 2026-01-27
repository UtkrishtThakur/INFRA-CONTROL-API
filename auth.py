from datetime import datetime, timedelta
from typing import Optional
import secrets
import hashlib

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from config import settings
from db import get_db
from models import User, EmailVerification
from schemas import UserCreate, UserOut, RegisterResponse, EmailVerificationResponse
from services.auth_email import send_verification_email

router = APIRouter(prefix="/auth", tags=["auth"])

# =========================
# Security
# =========================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# =========================
# Utils
# =========================

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta
        if expires_delta
        else timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def generate_email_token() -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return token, token_hash


# =========================
# Current User
# =========================

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        user_id: str | None = payload.get("sub")
        if not user_id:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise credentials_exception

    return user


# =========================
# Routes
# =========================

@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
def register_user(payload: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # 1. Create unverified user
    user = User(
        email=payload.email,
        password_hash=hash_password(payload.password),
        is_verified=False,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    # 2. Generate secure token
    token, token_hash = generate_email_token()

    # 3. Store hashed token
    verification = EmailVerification(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=datetime.utcnow() + timedelta(minutes=30),
        used=False,
    )

    db.add(verification)
    db.commit()

    # 4. Send verification link
    verification_link = (
        f"{settings.FRONTEND_URL}/verify-email"
        f"?token={token}&email={user.email}"
    )

    send_verification_email(user.email, verification_link)

    return {
        "message": "Verification link sent to your email"
    }


@router.get("/verify-email", response_model=EmailVerificationResponse)
def verify_email(token: str, email: str, db: Session = Depends(get_db)):
    # 1. Get user
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid verification link")

    # 2. Match hashed token
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    record = (
        db.query(EmailVerification)
        .filter(
            EmailVerification.user_id == user.id,
            EmailVerification.token_hash == token_hash,
            EmailVerification.used == False,
            EmailVerification.expires_at > datetime.utcnow(),
        )
        .first()
    )

    if not record:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired verification link",
        )

    # 3. Mark as verified
    user.is_verified = True
    record.used = True

    db.commit()

    return {"message": "Email verified successfully"}


@router.post("/login")
def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.email == form_data.username).first()

    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # 403 if not verified
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please verify your email first",
        )

    access_token = create_access_token(
        data={"sub": str(user.id), "email": user.email}
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


@router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user
