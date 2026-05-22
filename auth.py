from fastapi import HTTPException, status, Depends, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import os
import hashlib
import secrets

from database import db
from models import TokenResponse

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

security = HTTPBearer(auto_error=False)

def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(user_id: int, tenant_id: int, role: str) -> str:
    """Create JWT access token"""
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "tenant_id": tenant_id,
        "role": role,
        "type": "access",
        "exp": expire
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(user_id: int) -> Tuple[str, str]:
    """Create refresh token and its hash for storage"""
    refresh_token = secrets.token_urlsafe(64)
    refresh_token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    return refresh_token, refresh_token_hash

def verify_access_token(token: str) -> dict:
    """Verify and decode JWT access token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            raise JWTError
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> dict:
    """Dependency to get current authenticated user"""
    if not credentials:
        # Also check for API key (for device authentication)
        api_key = request.headers.get("X-API-Key")
        if api_key and api_key == os.getenv("ADMIN_API_KEY"):
            # System-level API key - return special context
            return {"user_id": None, "tenant_id": None, "role": "system", "is_api_key": True}
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    payload = verify_access_token(token)
    
    # Get user_id from token (this is the internal integer ID)
    user_id = int(payload.get("sub"))
    tenant_id = payload.get("tenant_id")
    
    # Verify user still exists and is active
    async with db.acquire() as conn:
        # FIXED: Changed from u.id = $1 to u.user_id = $1
        # Because the token contains the integer ID, but we need to query by UUID
        # Actually, let's keep u.id since user_id is integer ID
        user = await conn.fetchrow("""
            SELECT u.user_id, u.role, u.status, t.tenant_id
            FROM users u
            JOIN tenants t ON u.tenant_id = t.id
            WHERE u.id = $1 AND u.status = 'active' AND t.status = 'active'
        """, user_id)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User inactive or not found"
            )
    
    return {
        "user_id": user_id,
        "user_uuid": user["user_id"],
        "tenant_id": tenant_id,
        "role": user["role"]
    }

async def get_current_tenant(
    current_user: dict = Depends(get_current_user)
) -> int:
    """Get current tenant ID from authenticated user"""
    if current_user.get("is_api_key"):
        # API key authentication - return None, will need explicit tenant
        return None
    return current_user["tenant_id"]

def require_role(*allowed_roles: str):
    """Dependency factory for role-based access control"""
    async def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user.get("is_api_key"):
            return current_user
        if current_user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role {current_user['role']} not allowed. Required: {allowed_roles}"
            )
        return current_user
    return role_checker
