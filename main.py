from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional
import os
import asyncpg
import hashlib
import secrets
from datetime import datetime, timedelta

# ========== Simple Password Hashing ==========
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hash_obj = hashlib.sha256((salt + password).encode())
    return f"{salt}:{hash_obj.hexdigest()}"

def verify_password(plain: str, hashed: str) -> bool:
    try:
        salt, stored_hash = hashed.split(":")
        hash_obj = hashlib.sha256((salt + plain).encode())
        return hash_obj.hexdigest() == stored_hash
    except:
        return False

# ========== Simple Token Creation ==========
SECRET_KEY = os.getenv("SECRET_KEY", "my_secret_key_change_this")

def create_token(user_id: int, tenant_id: int) -> str:
    expire = datetime.utcnow() + timedelta(hours=24)
    data = f"{user_id}|{tenant_id}|{expire.timestamp()}"
    signature = hashlib.sha256((data + SECRET_KEY).encode()).hexdigest()
    return f"{data}|{signature}"

def verify_token(token: str):
    try:
        parts = token.split("|")
        if len(parts) != 4:
            return None
        user_id, tenant_id, expire_ts, signature = parts
        data = f"{user_id}|{tenant_id}|{expire_ts}"
        expected = hashlib.sha256((data + SECRET_KEY).encode()).hexdigest()
        if signature != expected:
            return None
        if float(expire_ts) < datetime.utcnow().timestamp():
            return None
        return {"user_id": int(user_id), "tenant_id": int(tenant_id)}
    except:
        return None

# ========== Models ==========
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

# ========== Database Setup ==========
DATABASE_URL = os.getenv("DATABASE_URL")
db_pool = None

async def init_db():
    async with db_pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS tenants (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                tenant_id INTEGER REFERENCES tenants(id),
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        print("Tables ready")

# ========== FastAPI App ==========
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    global db_pool
    db_pool = await asyncpg.create_pool(DATABASE_URL)
    await init_db()
    print("Started!")

@app.get("/")
async def root():
    return {"message": "API is running", "docs": "/docs"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.get("/debug")
async def debug():
    async with db_pool.acquire() as conn:
        user_count = await conn.fetchval("SELECT COUNT(*) FROM users")
        tenant_count = await conn.fetchval("SELECT COUNT(*) FROM tenants")
    return {
        "user_count": user_count,
        "tenant_count": tenant_count,
        "admin_key": os.getenv("ADMIN_API_KEY", "NOT SET")
    }

@app.post("/auth/register")
async def register(
    email: str,
    password: str,
    full_name: str,
    admin_api_key: Optional[str] = None
):
    VALID_KEY = os.getenv("ADMIN_API_KEY", "FIRST_USER_SETUP")
    
    async with db_pool.acquire() as conn:
        # Check if any user exists
        user_count = await conn.fetchval("SELECT COUNT(*) FROM users")
        
        if user_count == 0:
            # First user - need admin key
            if not admin_api_key or admin_api_key != VALID_KEY:
                raise HTTPException(403, "Invalid admin API key")
            
            # Create tenant
            tenant = await conn.fetchrow(
                "INSERT INTO tenants (name) VALUES ($1) RETURNING id",
                f"{full_name}'s Organization"
            )
            tenant_id = tenant["id"]
        else:
            raise HTTPException(400, "User already exists")
    
    # Create user
    password_hash = hash_password(password)
    
    async with db_pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO users (tenant_id, email, password_hash, full_name)
            VALUES ($1, $2, $3, $4)
        """, tenant_id, email, password_hash, full_name)
    
    return {"message": "User created", "email": email, "full_name": full_name}

@app.post("/auth/login")
async def login(email: str, password: str):
    async with db_pool.acquire() as conn:
        user = await conn.fetchrow(
            "SELECT id, password_hash, tenant_id FROM users WHERE email = $1",
            email
        )
        
        if not user:
            raise HTTPException(401, "Invalid email or password")
        
        if not verify_password(password, user["password_hash"]):
            raise HTTPException(401, "Invalid email or password")
        
        token = create_token(user["id"], user["tenant_id"])
        
        return {"access_token": token, "token_type": "bearer"}
