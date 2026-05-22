from pydantic import BaseModel, Field, EmailStr, validator
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum

# === Enums ===

class UserRole(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"
    MAINTAINER = "maintainer"

class DeviceType(str, Enum):
    LANDMINE_SHOE = "landmine_shoe"
    AI_SPECTACLES = "ai_spectacles"
    WASTE_SENSOR = "waste_sensor"
    DRONE = "drone"

class DeviceStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    MAINTENANCE = "maintenance"
    DECOMMISSIONED = "decommissioned"
    LOST = "lost"

class CommandType(str, Enum):
    REBOOT = "reboot"
    CALIBRATE = "calibrate"
    UPDATE_FIRMWARE = "update_firmware"
    COLLECT_DATA = "collect_data"
    EMERGENCY_STOP = "emergency_stop"

class CommandStatus(str, Enum):
    QUEUED = "queued"
    DELIVERED = "delivered"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

# === Tenant Models ===

class TenantCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    organization_type: str
    tier: str = "standard"
    settings: Dict[str, Any] = {}

class TenantResponse(BaseModel):
    tenant_id: str
    name: str
    organization_type: str
    tier: str
    status: str
    subscription_expires_at: Optional[datetime]
    settings: Dict[str, Any]
    created_at: datetime

# === User Models ===

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str = Field(..., min_length=1, max_length=100)
    role: UserRole
    permissions: List[str] = []

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    user_id: str
    email: str
    full_name: str
    role: UserRole
    permissions: List[str]
    status: str
    last_login: Optional[datetime]
    created_at: datetime

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class RefreshTokenRequest(BaseModel):
    refresh_token: str

# === Device Models ===

class DeviceCreate(BaseModel):
    device_name: str = Field(..., min_length=1, max_length=100)
    device_type: DeviceType
    serial_number: str = Field(..., min_length=1, max_length=100)
    firmware_version: Optional[str]
    hardware_version: Optional[str]
    metadata: Dict[str, Any] = {}
    
    @validator('serial_number')
    def validate_serial(cls, v):
        # Defense-grade serial number validation
        if not v.isalnum() and '-' not in v:
            raise ValueError('Serial number must be alphanumeric with optional dashes')
        return v.upper()

class DeviceUpdate(BaseModel):
    device_name: Optional[str]
    firmware_version: Optional[str]
    status: Optional[DeviceStatus]
    metadata: Optional[Dict[str, Any]]
    assigned_to_user_id: Optional[str]

class DeviceResponse(BaseModel):
    device_id: str
    device_name: str
    device_type: DeviceType
    serial_number: str
    firmware_version: Optional[str]
    status: DeviceStatus
    last_ping: Optional[datetime]
    last_known_location: Optional[Dict[str, float]]  # {"lat": x, "lng": y}
    metadata: Dict[str, Any]
    current_assigned_to: Optional[UserResponse]
    created_at: datetime
    updated_at: datetime

class DeviceLocationUpdate(BaseModel):
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)

class DeviceHeartbeat(BaseModel):
    device_id: str
    firmware_version: Optional[str]
    battery_level: Optional[float] = Field(None, ge=0, le=100)
    metadata: Dict[str, Any] = {}

# === Command Models ===

class CommandSend(BaseModel):
    device_id: str
    command_type: CommandType
    payload: Dict[str, Any] = {}
    priority: int = Field(1, ge=0, le=2)

class CommandResponse(BaseModel):
    command_id: str
    device_id: str
    command_type: CommandType
    status: CommandStatus
    queued_at: datetime
    delivered_at: Optional[datetime]
    completed_at: Optional[datetime]
    result: Optional[Dict[str, Any]]
    error_message: Optional[str]

class CommandStatusUpdate(BaseModel):
    command_id: str
    status: CommandStatus
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None

# === Group Models ===

class DeviceGroupCreate(BaseModel):
    group_name: str
    description: Optional[str]

class DeviceGroupResponse(BaseModel):
    group_id: str
    group_name: str
    description: Optional[str]
    device_count: int
    created_at: datetime

# === Audit Models ===

class AuditLogResponse(BaseModel):
    log_id: str
    user_id: Optional[str]
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    ip_address: Optional[str]
    status: Optional[str]
    details: Optional[Dict[str, Any]]
    created_at: datetime