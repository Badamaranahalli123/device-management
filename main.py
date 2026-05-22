from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional
import os
import asyncpg
import hashlib
import secrets
from datetime import datetime, timedelta
import traceback

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
                organization_type TEXT DEFAULT 'research',
                tier TEXT DEFAULT 'standard',
                status TEXT DEFAULT 'active',
                settings JSONB DEFAULT '{}',
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                tenant_id INTEGER REFERENCES tenants(id),
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT DEFAULT 'admin',
                permissions JSONB DEFAULT '[]',
                status TEXT DEFAULT 'active',
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
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

# ========== Register Endpoint ==========
@app.post("/auth/register")
async def register(
    email: str,
    password: str,
    full_name: str,
    admin_api_key: Optional[str] = None
):
    try:
        print(f"DEBUG: Register called with email={email}")
        
        VALID_KEY = os.getenv("ADMIN_API_KEY", "FIRST_USER_SETUP")
        print(f"DEBUG: VALID_KEY={VALID_KEY}")
        
        async with db_pool.acquire() as conn:
            user_count = await conn.fetchval("SELECT COUNT(*) FROM users")
            print(f"DEBUG: user_count={user_count}")
            
            if user_count == 0:
                # First user - need admin key
                if not admin_api_key or admin_api_key != VALID_KEY:
                    raise HTTPException(403, "Invalid admin API key")
                
                # Create tenant with all required fields
                tenant = await conn.fetchrow("""
                    INSERT INTO tenants (name, organization_type, tier, status) 
                    VALUES ($1, 'research', 'standard', 'active') 
                    RETURNING id
                """, f"{full_name}'s Organization")
                tenant_id = tenant["id"]
                print(f"DEBUG: tenant created with id={tenant_id}")
            else:
                raise HTTPException(400, "User already exists")
        
        # Create user
        password_hash = hash_password(password)
        print(f"DEBUG: password hashed successfully")
        
        async with db_pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO users (tenant_id, email, password_hash, full_name, role, status)
                VALUES ($1, $2, $3, $4, 'admin', 'active')
            """, tenant_id, email, password_hash, full_name)
            print(f"DEBUG: user inserted successfully")
        
        return {"message": "User created successfully", "email": email, "full_name": full_name}
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"DEBUG ERROR: {type(e).__name__}: {str(e)}")
        traceback.print_exc()
        raise HTTPException(500, f"Error: {str(e)}")

# ========== Login Endpoint ==========
@app.post("/auth/login")
async def login(email: str, password: str):
    async with db_pool.acquire() as conn:
        user = await conn.fetchrow("""
            SELECT id, password_hash, tenant_id, role 
            FROM users 
            WHERE email = $1 AND status = 'active'
        """, email)
        
        if not user:
            raise HTTPException(401, "Invalid email or password")
        
        if not verify_password(password, user["password_hash"]):
            raise HTTPException(401, "Invalid email or password")
        
        token = create_token(user["id"], user["tenant_id"])
        
        return {"access_token": token, "token_type": "bearer"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
