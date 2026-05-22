from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from database import db, init_database
from auth import (
    hash_password, verify_password, create_access_token, create_refresh_token,
    get_current_user
)
from models import UserCreate, UserLogin, TokenResponse, RefreshTokenRequest
from audit import log_audit
import devices, commands

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await db.connect()
    await init_database()
    logger.info("Database connected and initialized")
    yield
    # Shutdown
    await db.close()
    logger.info("Database disconnected")

app = FastAPI(
    title="Multi-Tenant Device Management API",
    description="Defense/IoT Device & User Management System",
    version="1.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(devices.router)
app.include_router(commands.router)

# === Authentication Endpoints ===

@app.post("/auth/register", status_code=201)
async def register_user(
    user: UserCreate,
    admin_api_key: str = None  # First user needs admin API key
):
    """Register a new user (first user requires admin API key)"""
    from database import db
    
    # Check if this is the first user
    async with db.acquire() as conn:
        user_count = await conn.fetchval("SELECT COUNT(*) FROM users")
        
        if user_count == 0:
            # First user - create tenant as well
            if not admin_api_key or admin_api_key != "FIRST_USER_SETUP":
                raise HTTPException(403, "First user setup requires valid setup key")
            
            # Create tenant
            tenant = await conn.fetchrow("""
                INSERT INTO tenants (name, organization_type, tier)
                VALUES ($1, $2, 'enterprise')
                RETURNING id, tenant_id
            """, f"{user.full_name}'s Organization", "research_lab")
            
            tenant_id = tenant["id"]
        else:
            # Normal registration requires tenant context (not implemented in this simplified version)
            raise HTTPException(400, "User registration via invite only")
    
    # Create user
    password_hash = hash_password(user.password)
    
    async with db.acquire() as conn:
        new_user = await conn.fetchrow("""
            INSERT INTO users (tenant_id, email, password_hash, full_name, role, permissions)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING user_id, email, full_name, role
        """, tenant_id, user.email, password_hash, user.full_name, 
           user.role.value, user.permissions)
    
    await log_audit(
        tenant_id=tenant_id,
        user_id=new_user["user_id"],
        action="user.register",
        resource_type="user",
        resource_id=str(new_user["user_id"]),
        status="success"
    )
    
    return {"message": "User created successfully", "user": dict(new_user)}

@app.post("/auth/login", response_model=TokenResponse)
async def login(user_login: UserLogin, request: Request):
    """Login and get access token"""
    async with db.acquire() as conn:
        db_user = await conn.fetchrow("""
            SELECT u.id, u.user_id, u.email, u.password_hash, u.role, u.status,
                   u.tenant_id, t.tenant_id as tenant_uuid
            FROM users u
            JOIN tenants t ON u.tenant_id = t.id
            WHERE u.email = $1
        """, user_login.email)
        
        if not db_user or not verify_password(user_login.password, db_user["password_hash"]):
            raise HTTPException(401, "Invalid credentials")
        
        if db_user["status"] != "active":
            raise HTTPException(401, "Account is disabled")
        
        # Update last login
        await conn.execute("""
            UPDATE users SET last_login = NOW() WHERE id = $1
        """, db_user["id"])
    
    # Create tokens
    access_token = create_access_token(db_user["id"], db_user["tenant_id"], db_user["role"])
    refresh_token, refresh_hash = create_refresh_token(db_user["id"])
    
    # Store refresh token
    async with db.acquire() as conn:
        await conn.execute("""
            INSERT INTO user_sessions (user_id, refresh_token_hash, expires_at, ip_address, user_agent)
            VALUES ($1, $2, NOW() + INTERVAL '7 days', $3, $4)
        """, db_user["id"], refresh_hash, request.client.host, request.headers.get("user-agent"))
    
    await log_audit(
        tenant_id=db_user["tenant_id"],
        user_id=db_user["id"],
        action="user.login",
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent"),
        status="success"
    )
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=3600
    )

@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh_token(refresh_request: RefreshTokenRequest, request: Request):
    """Refresh access token"""
    import hashlib
    
    refresh_hash = hashlib.sha256(refresh_request.refresh_token.encode()).hexdigest()
    
    async with db.acquire() as conn:
        session = await conn.fetchrow("""
            SELECT s.user_id, u.id, u.tenant_id, u.role, u.status
            FROM user_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.refresh_token_hash = $1 
              AND s.expires_at > NOW() 
              AND s.revoked = FALSE
        """, refresh_hash)
        
        if not session or session["status"] != "active":
            raise HTTPException(401, "Invalid or expired refresh token")
        
        # Revoke old session and create new one
        await conn.execute("""
            UPDATE user_sessions SET revoked = TRUE 
            WHERE refresh_token_hash = $1
        """, refresh_hash)
    
    # Create new tokens
    new_access = create_access_token(session["user_id"], session["tenant_id"], session["role"])
    new_refresh, new_hash = create_refresh_token(session["user_id"])
    
    async with db.acquire() as conn:
        await conn.execute("""
            INSERT INTO user_sessions (user_id, refresh_token_hash, expires_at, ip_address, user_agent)
            VALUES ($1, $2, NOW() + INTERVAL '7 days', $3, $4)
        """, session["user_id"], new_hash, request.client.host, request.headers.get("user-agent"))
    
    return TokenResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        expires_in=3600
    )

@app.post("/auth/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """Logout (revoke current session) - requires bearer token"""
    # In a real implementation, you'd revoke the specific session
    return {"message": "Logged out successfully"}

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "device-management-api"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
