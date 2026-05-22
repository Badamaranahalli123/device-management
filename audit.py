from database import db
from typing import Optional, Dict, Any
import json

async def log_audit(
    tenant_id: Optional[int],
    user_id: Optional[int],
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    old_value: Optional[Dict] = None,
    new_value: Optional[Dict] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    status: str = "success",
    details: Optional[Dict] = None
):
    """Log an audit event"""
    try:
        async with db.acquire() as conn:
            await conn.execute("""
                INSERT INTO audit_logs 
                (tenant_id, user_id, action, resource_type, resource_id, 
                 old_value, new_value, ip_address, user_agent, status, details)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            """, tenant_id, user_id, action, resource_type, resource_id,
               json.dumps(old_value) if old_value else None,
               json.dumps(new_value) if new_value else None,
               ip_address, user_agent, status,
               json.dumps(details) if details else None)
    except Exception as e:
        # Don't let audit logging failure break the main operation
        print(f"Audit log failed: {e}")

async def get_audit_logs(
    tenant_id: int,
    user_id: Optional[int] = None,
    action: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> list:
    """Retrieve audit logs with filters"""
    query = """
        SELECT log_id, user_id, action, resource_type, resource_id, 
               ip_address, status, details, created_at
        FROM audit_logs
        WHERE tenant_id = $1
    """
    params = [tenant_id]
    param_idx = 2
    
    if user_id:
        query += f" AND user_id = ${param_idx}"
        params.append(user_id)
        param_idx += 1
    
    if action:
        query += f" AND action = ${param_idx}"
        params.append(action)
        param_idx += 1
    
    query += " ORDER BY created_at DESC LIMIT $" + str(param_idx) + " OFFSET $" + str(param_idx + 1)
    params.extend([limit, offset])
    
    async with db.acquire() as conn:
        rows = await conn.fetch(query, *params)
    
    return [dict(row) for row in rows]