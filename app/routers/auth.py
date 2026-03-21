from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from app.core.auth import (
    authenticate_user, register_user,
    create_access_token, get_current_user
)

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    username: str
    password: str
    role: str = "readonly"


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


class UserResponse(BaseModel):
    username: str
    role: str


@router.post("/register", status_code=201)
async def register(request: RegisterRequest):
    """
    Register a new user.
    Role options: readonly, operator, admin
    """
    if len(request.password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 6 characters"
        )

    success = register_user(
        username=request.username,
        password=request.password,
        role=request.role
    )

    if not success:
        raise HTTPException(
            status_code=409,
            detail=f"Username '{request.username}' already exists"
        )

    return {"message": f"User '{request.username}' registered successfully", "role": request.role}


@router.post("/login", response_model=TokenResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Login with username + password.
    Returns a JWT access token valid for 24 hours.
    """
    user = authenticate_user(form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token({
        "sub": user["username"],
        "role": user["role"]
    })

    return TokenResponse(
        access_token=token,
        username=user["username"],
        role=user["role"]
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    """Returns the currently authenticated user's info."""
    return UserResponse(
        username=current_user["username"],
        role=current_user["role"]
    )