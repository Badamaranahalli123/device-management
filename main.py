from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import logging
import os
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt
import asyncpg

from database import db

# ========== Setup ==========
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("SECRET_KEY", "temp_secret_key_change_this")
ALGORITHM = "HS256"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ========== Pydantic Models ==========
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

# ========== Helper Functions ==========
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_token(user_id: int, tenant_id: int, role: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=24)
    payload = {"sub": user_id, "tenant_id": tenant_id, "role": role, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# ========== Database Initialization ==========
async def init_tables():
    """Create tables if they don't exist"""
    async with db.acquire() as conn:
        # Create tenants table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS tenants (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                organization_type VARCHAR(50) DEFAULT 'research',
                tier VARCHAR(20) DEFAULT 'standard',
                status VARCHAR(20) DEFAULT 'active',
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        
        # Create users table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                tenant_id INTEGER REFERENCES tenants(id),
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                full_name VARCHAR(100) NOT NULL,
                role VARCHAR(30) DEFAULT 'admin',
                permissions JSONB DEFAULT '[]',
                status VARCHAR(20) DEFAULT 'active',
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        
        logger.info("Tables created/verified")

# ========== Lifespan ==========
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await db.connect()
    await init_tables()
    logger.info("Database connected and tables ready")
    yield
    # Shutdown
    await db.close()
    logger.info("Database disconnected")

# ========== FastAPI App ==========
app = FastAPI(
    title="Device Management API",
    description="Simple working API",
    version="1.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== Health Check ==========
@app.get("/")
async def root():
    return {"message": "API is running", "docs": "/docs", "health": "/health"}

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "device-management-api"}

# ========== Register Endpoint ==========
@app.post("/auth/register", status_code=201)
async def register_user(user: UserRegister, admin_api_key: Optional[str] = None):
    """Register first user (admin)"""
    VALID_KEY = os.getenv("ADMIN_API_KEY", "FIRST_USER_SETUP")
    
    async with db.acquire() as conn:
        # Check if any user exists
        user_count = await conn.fetchval("SELECT COUNT(*) FROM users")
        
        if user_count == 0:
            # First user - validate admin key
            if not admin_api_key or admin_api_key != VALID_KEY:
                raise HTTPException(403, "Invalid admin API key")
            
            # Create tenant
            tenant = await conn.fetchrow("""
                INSERT INTO tenants (name, organization_type)
                VALUES ($1, 'research')
                RETURNING id
            """, f"{user.full_name}'s Organization")
            tenant_id = tenant["id"]
        else:
            raise HTTPException(400, "User already exists. Registration closed.")
    
    # Create user
    password_hash = hash_password(user.password)
    
    async with db.acquire() as conn:
        await conn.execute("""
            INSERT INTO users (tenant_id, email, password_hash, full_name, role, permissions)
            VALUES ($1, $2, $3, $4, 'admin', '["*"]')
        """, tenant_id, user.email, password_hash, user.full_name)
    
    return {"message": "User created successfully", "email": user.email, "full_name": user.full_name}

# ========== Login Endpoint ==========
@app.post("/auth/login", response_model=TokenResponse)
async def login_user(user: UserLogin):
    """Login and get access token"""
    async with db.acquire() as conn:
        db_user = await conn.fetchrow("""
            SELECT id, email, password_hash, role, tenant_id
            FROM users
            WHERE email = $1 AND status = 'active'
        """, user.email)
        
        if not db_user:
            raise HTTPException(401, "Invalid email or password")
        
        if not verify_password(user.password, db_user["password_hash"]):
            raise HTTPException(401, "Invalid email or password")
    
    # Create token
    token = create_token(db_user["id"], db_user["tenant_id"], db_user["role"])
    
    return {"access_token": token, "token_type": "bearer"}

# ========== Debug Endpoint ==========
@app.get("/debug")
async def debug_info():
    """Check if environment variables are loaded"""
    async with db.acquire() as conn:
        user_count = await conn.fetchval("SELECT COUNT(*) FROM users")
        tenant_count = await conn.fetchval("SELECT COUNT(*) FROM tenants")
    
    return {
        "status": "debug",
        "database_connected": True,
        "user_count": user_count,
        "tenant_count": tenant_count,
        "admin_api_key_loaded": os.getenv("ADMIN_API_KEY") is not None,
        "admin_api_key_value": os.getenv("ADMIN_API_KEY"),
        "secret_key_loaded": os.getenv("SECRET_KEY") is not None,
    }
