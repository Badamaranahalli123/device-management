import asyncpg
from asyncpg.pool import Pool
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional
import os
import logging
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)

class Database:
    def __init__(self):
        self.pool: Optional[Pool] = None
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=5)
    )
    async def connect(self):
        """Create database connection pool with retry logic"""
        self.pool = await asyncpg.create_pool(
            os.getenv("DATABASE_URL"),
            min_size=10,
            max_size=50,
            command_timeout=60,
            max_queries=50000,
            max_inactive_connection_lifetime=300
        )
        logger.info("Database connection pool created")
    
    async def close(self):
        if self.pool:
            await self.pool.close()
            logger.info("Database connection pool closed")
    
    @asynccontextmanager
    async def acquire(self) -> AsyncGenerator[asyncpg.Connection, None]:
        async with self.pool.acquire() as conn:
            yield conn
    
    async def execute(self, query: str, *args):
        async with self.acquire() as conn:
            return await conn.execute(query, *args)
    
    async def fetch(self, query: str, *args):
        async with self.acquire() as conn:
            return await conn.fetch(query, *args)
    
    async def fetchrow(self, query: str, *args):
        async with self.acquire() as conn:
            return await conn.fetchrow(query, *args)
    
    async def fetchval(self, query: str, *args):
        async with self.acquire() as conn:
            return await conn.fetchval(query, *args)

db = Database()

async def init_database():
    """Initialize database schema with multi-tenant support"""
    
    # Read and execute initialization SQL
    with open("init_db.sql", "r") as f:
        sql = f.read()
    
    async with db.acquire() as conn:
        await conn.execute(sql)
        logger.info("Database schema initialized")