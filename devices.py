from fastapi import APIRouter, HTTPException, status, Depends, Request
from typing import List, Optional
from datetime import datetime

from database import db
from models import (
    DeviceCreate, DeviceUpdate, DeviceResponse, DeviceLocationUpdate,
    DeviceHeartbeat, UserRole
)
from auth import get_current_user, get_current_tenant, require_role
from audit import log_audit
import json

router = APIRouter(prefix="/devices", tags=["Devices"])

@router.post("", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
async def register_device(
    device: DeviceCreate,
    request: Request,
    current_user: dict = Depends(require_role(UserRole.ADMIN, UserRole.MAINTAINER))
):
    """Register a new device (Admin/Maintainer only)"""
    tenant_id = current_user["tenant_id"]
    
    async with db.acquire() as conn:
        # Check if serial number already exists in this tenant
        existing = await conn.fetchval("""
            SELECT 1 FROM devices WHERE serial_number = $1 AND tenant_id = $2
        """, device.serial_number, tenant_id)
        
        if existing:
            raise HTTPException(409, f"Device with serial {device.serial_number} already exists")
        
        # Insert device
        row = await conn.fetchrow("""
            INSERT INTO devices (tenant_id, device_name, device_type, serial_number, 
                                 firmware_version, hardware_version, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING device_id, device_name, device_type, serial_number, firmware_version,
                      status, metadata, created_at, updated_at
        """, tenant_id, device.device_name, device.device_type.value, device.serial_number,
           device.firmware_version, device.hardware_version, json.dumps(device.metadata))
    
    # Log audit
    await log_audit(
        tenant_id=tenant_id,
        user_id=current_user.get("user_id"),
        action="device.register",
        resource_type="device",
        resource_id=str(row["device_id"]),
        new_value={"device_name": device.device_name, "device_type": device.device_type.value},
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent"),
        status="success"
    )
    
    return dict(row)

@router.get("", response_model=List[DeviceResponse])
async def list_devices(
    request: Request,
    device_type: Optional[str] = None,
    status: Optional[str] = None,
    group_id: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    current_user: dict = Depends(get_current_user)
):
    """List devices with filters"""
    tenant_id = current_user["tenant_id"]
    
    query = """
        SELECT d.device_id, d.device_name, d.device_type, d.serial_number,
               d.firmware_version, d.status, d.last_ping, d.metadata,
               d.created_at, d.updated_at,
               ST_X(d.last_known_location::geometry) as lat,
               ST_Y(d.last_known_location::geometry) as lng,
               u.user_id as assigned_user_id, u.full_name as assigned_user_name
        FROM devices d
        LEFT JOIN users u ON d.current_assigned_to = u.id
        WHERE d.tenant_id = $1
    """
    params = [tenant_id]
    param_idx = 2
    
    if device_type:
        query += f" AND d.device_type = ${param_idx}"
        params.append(device_type)
        param_idx += 1
    
    if status:
        query += f" AND d.status = ${param_idx}"
        params.append(status)
        param_idx += 1
    
    if group_id:
        query += f" AND d.id IN (SELECT device_id FROM device_group_members WHERE group_id = (SELECT id FROM device_groups WHERE group_id = ${param_idx} AND tenant_id = $1))"
        params.append(group_id)
        param_idx += 1
    
    query += f" ORDER BY d.created_at DESC LIMIT ${param_idx} OFFSET ${param_idx + 1}"
    params.extend([limit, offset])
    
    async with db.acquire() as conn:
        rows = await conn.fetch(query, *params)
    
    devices = []
    for row in rows:
        device_dict = dict(row)
        if row["lat"] and row["lng"]:
            device_dict["last_known_location"] = {"lat": row["lat"], "lng": row["lng"]}
        else:
            device_dict["last_known_location"] = None
        
        if row["assigned_user_id"]:
            device_dict["current_assigned_to"] = {
                "user_id": row["assigned_user_id"],
                "full_name": row["assigned_user_name"]
            }
        else:
            device_dict["current_assigned_to"] = None
        
        devices.append(device_dict)
    
    return devices

@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get device details"""
    tenant_id = current_user["tenant_id"]
    
    async with db.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT d.device_id, d.device_name, d.device_type, d.serial_number,
                   d.firmware_version, d.status, d.last_ping, d.metadata,
                   d.created_at, d.updated_at,
                   ST_X(d.last_known_location::geometry) as lat,
                   ST_Y(d.last_known_location::geometry) as lng,
                   u.user_id as assigned_user_id, u.full_name as assigned_user_name
            FROM devices d
            LEFT JOIN users u ON d.current_assigned_to = u.id
            WHERE d.device_id = $1 AND d.tenant_id = $2
        """, device_id, tenant_id)
        
        if not row:
            raise HTTPException(404, f"Device {device_id} not found")
    
    result = dict(row)
    if row["lat"] and row["lng"]:
        result["last_known_location"] = {"lat": row["lat"], "lng": row["lng"]}
    
    return result

@router.patch("/{device_id}")
async def update_device(
    device_id: str,
    update: DeviceUpdate,
    request: Request,
    current_user: dict = Depends(require_role(UserRole.ADMIN, UserRole.MAINTAINER))
):
    """Update device (Admin/Maintainer only)"""
    tenant_id = current_user["tenant_id"]
    
    # Build update query dynamically
    updates = []
    params = []
    param_idx = 1
    
    if update.device_name:
        updates.append(f"device_name = ${param_idx}")
        params.append(update.device_name)
        param_idx += 1
    
    if update.firmware_version:
        updates.append(f"firmware_version = ${param_idx}")
        params.append(update.firmware_version)
        param_idx += 1
    
    if update.status:
        updates.append(f"status = ${param_idx}")
        params.append(update.status.value)
        param_idx += 1
    
    if update.metadata:
        updates.append(f"metadata = ${param_idx}")
        params.append(json.dumps(update.metadata))
        param_idx += 1
    
    if update.assigned_to_user_id:
        # Get user ID from UUID
        user_id = await get_user_id_by_uuid(update.assigned_to_user_id, tenant_id)
        if not user_id:
            raise HTTPException(404, f"User {update.assigned_to_user_id} not found")
        updates.append(f"current_assigned_to = ${param_idx}")
        params.append(user_id)
        param_idx += 1
    
    if not updates:
        raise HTTPException(400, "No fields to update")
    
    params.append(device_id)
    params.append(tenant_id)
    
    async with db.acquire() as conn:
        result = await conn.execute(f"""
            UPDATE devices 
            SET {', '.join(updates)}
            WHERE device_id = ${param_idx} AND tenant_id = ${param_idx + 1}
        """, *params)
        
        if result == "UPDATE 0":
            raise HTTPException(404, f"Device {device_id} not found")
    
    await log_audit(
        tenant_id=tenant_id,
        user_id=current_user.get("user_id"),
        action="device.update",
        resource_type="device",
        resource_id=device_id,
        new_value=update.dict(exclude_unset=True),
        ip_address=request.client.host,
        status="success"
    )
    
    return {"status": "updated", "device_id": device_id}

@router.post("/{device_id}/location")
async def update_device_location(
    device_id: str,
    location: DeviceLocationUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update device GPS location"""
    tenant_id = current_user["tenant_id"]
    
    async with db.acquire() as conn:
        result = await conn.execute("""
            UPDATE devices 
            SET last_known_location = ST_SetSRID(ST_MakePoint($1, $2), 4326),
                last_ping = NOW()
            WHERE device_id = $3 AND tenant_id = $4
        """, location.longitude, location.latitude, device_id, tenant_id)
        
        if result == "UPDATE 0":
            raise HTTPException(404, f"Device {device_id} not found")
    
    return {"status": "updated", "device_id": device_id, "location": location.dict()}

@router.post("/heartbeat")
async def device_heartbeat(
    heartbeat: DeviceHeartbeat,
    request: Request
):
    """Device heartbeat endpoint (no auth - device uses its own API key)"""
    # Verify device exists
    async with db.acquire() as conn:
        result = await conn.execute("""
            UPDATE devices 
            SET last_ping = NOW(),
                firmware_version = COALESCE($1, firmware_version),
                metadata = metadata || $2
            WHERE device_id = $3
        """, heartbeat.firmware_version, 
           json.dumps(heartbeat.metadata), 
           heartbeat.device_id)
        
        if result == "UPDATE 0":
            raise HTTPException(404, f"Device {heartbeat.device_id} not found")
    
    return {"status": "ok", "last_ping": datetime.utcnow().isoformat()}

async def get_user_id_by_uuid(user_uuid: str, tenant_id: int) -> int:
    """Helper to get internal user ID from UUID"""
    async with db.acquire() as conn:
        return await conn.fetchval("""
            SELECT id FROM users WHERE user_id = $1 AND tenant_id = $2
        """, user_uuid, tenant_id)