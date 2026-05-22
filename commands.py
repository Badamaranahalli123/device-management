from fastapi import APIRouter, HTTPException, status, Depends, Request, BackgroundTasks
from typing import List, Optional
from datetime import datetime
import json
import uuid

from database import db
from models import CommandSend, CommandResponse, CommandStatusUpdate, CommandStatus, UserRole
from auth import get_current_user, get_current_tenant, require_role
from audit import log_audit
import redis
import os

redis_client = redis.from_url(os.getenv("REDIS_URL"))

router = APIRouter(prefix="/commands", tags=["Commands"])

@router.post("", response_model=CommandResponse, status_code=status.HTTP_202_ACCEPTED)
async def send_command(
    command: CommandSend,
    background_tasks: BackgroundTasks,
    request: Request,
    current_user: dict = Depends(require_role(UserRole.ADMIN, UserRole.OPERATOR, UserRole.MAINTAINER))
):
    """Send a command to a device"""
    tenant_id = current_user["tenant_id"]
    
    # Get device internal ID
    async with db.acquire() as conn:
        device = await conn.fetchrow("""
            SELECT id, device_id, status FROM devices 
            WHERE device_id = $1 AND tenant_id = $2
        """, command.device_id, tenant_id)
        
        if not device:
            raise HTTPException(404, f"Device {command.device_id} not found")
        
        if device["status"] != "active":
            raise HTTPException(400, f"Device {command.device_id} is {device['status']}, cannot send commands")
        
        # Store command in database
        command_id = str(uuid.uuid4())
        await conn.execute("""
            INSERT INTO commands (command_id, tenant_id, device_id, command_type, 
                                  payload, priority, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        """, command_id, tenant_id, device["id"], command.command_type.value,
           json.dumps(command.payload), command.priority, current_user.get("user_id"))
        
        # Queue in Redis for device polling
        redis_client.rpush(
            f"device:{command.device_id}:commands",
            json.dumps({
                "command_id": command_id,
                "command_type": command.command_type.value,
                "payload": command.payload,
                "priority": command.priority
            })
        )
        
        # For critical commands, notify via WebSocket (if implemented)
        if command.priority == 0:
            background_tasks.add_task(notify_critical_command, command.device_id, command_id)
    
    await log_audit(
        tenant_id=tenant_id,
        user_id=current_user.get("user_id"),
        action="command.send",
        resource_type="command",
        resource_id=command_id,
        new_value={"device_id": command.device_id, "command_type": command.command_type.value},
        ip_address=request.client.host,
        status="success"
    )
    
    return CommandResponse(
        command_id=command_id,
        device_id=command.device_id,
        command_type=command.command_type,
        status=CommandStatus.QUEUED,
        queued_at=datetime.utcnow(),
        delivered_at=None,
        completed_at=None,
        result=None,
        error_message=None
    )

@router.get("/device/{device_id}/next")
async def get_next_command(
    device_id: str,
    request: Request
):
    """Device polls this to get its next command (uses device API key)"""
    # Verify device exists
    async with db.acquire() as conn:
        device = await conn.fetchrow("""
            SELECT id, device_id FROM devices WHERE device_id = $1
        """, device_id)
        
        if not device:
            raise HTTPException(404, f"Device {device_id} not found")
    
    # Pop from Redis queue
    command_data = redis_client.lpop(f"device:{device_id}:commands")
    
    if not command_data:
        return {"has_command": False}
    
    command = json.loads(command_data)
    command_id = command["command_id"]
    
    # Update status in database
    async with db.acquire() as conn:
        await conn.execute("""
            UPDATE commands 
            SET status = 'delivered', delivered_at = NOW()
            WHERE command_id = $1 AND status = 'queued'
        """, command_id)
    
    return {
        "has_command": True,
        "command_id": command_id,
        "command_type": command["command_type"],
        "payload": command["payload"]
    }

@router.put("/status")
async def update_command_status(
    update: CommandStatusUpdate,
    request: Request
):
    """Device updates command execution status"""
    async with db.acquire() as conn:
        # Get command details
        command = await conn.fetchrow("""
            SELECT c.*, d.device_id as device_uuid 
            FROM commands c
            JOIN devices d ON c.device_id = d.id
            WHERE c.command_id = $1
        """, update.command_id)
        
        if not command:
            raise HTTPException(404, f"Command {update.command_id} not found")
        
        # Update status
        if update.status in [CommandStatus.COMPLETED, CommandStatus.FAILED]:
            await conn.execute("""
                UPDATE commands 
                SET status = $1, completed_at = NOW(),
                    result = $2, error_message = $3
                WHERE command_id = $4
            """, update.status.value, json.dumps(update.result) if update.result else None,
               update.error_message, update.command_id)
        elif update.status == CommandStatus.IN_PROGRESS:
            await conn.execute("""
                UPDATE commands 
                SET status = $1, started_at = NOW()
                WHERE command_id = $2
            """, update.status.value, update.command_id)
    
    return {"status": "updated", "command_id": update.command_id}

@router.get("/{command_id}", response_model=CommandResponse)
async def get_command_status(
    command_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get command status"""
    tenant_id = current_user["tenant_id"]
    
    async with db.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT c.command_id, d.device_id as device_uuid, c.command_type, c.status,
                   c.queued_at, c.delivered_at, c.started_at, c.completed_at,
                   c.result, c.error_message
            FROM commands c
            JOIN devices d ON c.device_id = d.id
            WHERE c.command_id = $1 AND c.tenant_id = $2
        """, command_id, tenant_id)
        
        if not row:
            raise HTTPException(404, f"Command {command_id} not found")
    
    return CommandResponse(
        command_id=row["command_id"],
        device_id=row["device_uuid"],
        command_type=row["command_type"],
        status=row["status"],
        queued_at=row["queued_at"],
        delivered_at=row["delivered_at"],
        completed_at=row["completed_at"],
        result=row["result"],
        error_message=row["error_message"]
    )

@router.get("/device/{device_id}/history", response_model=List[CommandResponse])
async def get_device_command_history(
    device_id: str,
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get command history for a device"""
    tenant_id = current_user["tenant_id"]
    
    async with db.acquire() as conn:
        rows = await conn.fetch("""
            SELECT c.command_id, d.device_id as device_uuid, c.command_type, c.status,
                   c.queued_at, c.delivered_at, c.started_at, c.completed_at,
                   c.result, c.error_message
            FROM commands c
            JOIN devices d ON c.device_id = d.id
            WHERE d.device_id = $1 AND c.tenant_id = $2
            ORDER BY c.queued_at DESC
            LIMIT $3
        """, device_id, tenant_id, limit)
    
    return [CommandResponse(
        command_id=row["command_id"],
        device_id=row["device_uuid"],
        command_type=row["command_type"],
        status=row["status"],
        queued_at=row["queued_at"],
        delivered_at=row["delivered_at"],
        completed_at=row["completed_at"],
        result=row["result"],
        error_message=row["error_message"]
    ) for row in rows]

async def notify_critical_command(device_id: str, command_id: str):
    """Background task to notify about critical commands"""
    # Placeholder for WebSocket/notification logic
    print(f"CRITICAL COMMAND: {command_id} for device {device_id}")