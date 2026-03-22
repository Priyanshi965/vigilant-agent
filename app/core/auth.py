from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.config import get_settings
from app.database import get_db

settings = get_settings()

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(hours=settings.token_expire_hours)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.secret_key, algorithm="HS256")


def verify_token(token: str) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return payload
    except JWTError:
        raise credentials_exception


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> dict:
    """
    FastAPI dependency — extracts and validates the current user from JWT token.
    Looks up user in database to confirm they still exist and are active.
    """
    from app.models.db_models import User

    payload = verify_token(token)
    username = payload.get("sub")
    role = payload.get("role", "readonly")

    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"username": username, "role": role, "user_id": user.id}


def register_user(username: str, password: str, role: str = "readonly", db: Session = None) -> bool:
    """Register a new user in the database. Returns False if username exists."""
    from app.models.db_models import User

    existing = db.query(User).filter(User.username == username).first()
    if existing:
        return False

    user = User(
        username=username,
        hashed_password=get_password_hash(password),
        role=role
    )
    db.add(user)
    db.commit()
    return True


def authenticate_user(username: str, password: str, db: Session = None) -> Optional[dict]:
    """Verify username + password against database."""
    from app.models.db_models import User

    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return {"username": user.username, "role": user.role, "user_id": user.id}