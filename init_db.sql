-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ==================== TENANTS (Organizations) ====================
CREATE TABLE tenants (
    id SERIAL PRIMARY KEY,
    tenant_id UUID UNIQUE DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    organization_type VARCHAR(50) NOT NULL, -- 'military_unit', 'hospital', 'municipality', 'research_lab'
    tier VARCHAR(20) DEFAULT 'standard', -- 'standard', 'premium', 'enterprise'
    status VARCHAR(20) DEFAULT 'active', -- 'active', 'suspended', 'deleted'
    subscription_expires_at TIMESTAMPTZ,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ==================== USERS with RBAC ====================
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    user_id UUID UNIQUE DEFAULT uuid_generate_v4(),
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    role VARCHAR(30) NOT NULL, -- 'admin', 'operator', 'viewer', 'maintainer'
    permissions JSONB DEFAULT '[]', -- Fine-grained permissions override
    status VARCHAR(20) DEFAULT 'active', -- 'active', 'disabled', 'pending'
    last_login TIMESTAMPTZ,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(255),
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);

-- ==================== DEVICES ====================
CREATE TABLE devices (
    id SERIAL PRIMARY KEY,
    device_id UUID UNIQUE DEFAULT uuid_generate_v4(),
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_name VARCHAR(100) NOT NULL,
    device_type VARCHAR(50) NOT NULL, -- 'landmine_shoe', 'ai_spectacles', 'waste_sensor', 'drone'
    serial_number VARCHAR(100) UNIQUE NOT NULL,
    firmware_version VARCHAR(20),
    hardware_version VARCHAR(20),
    status VARCHAR(20) DEFAULT 'active', -- 'active', 'inactive', 'maintenance', 'decommissioned', 'lost'
    last_ping TIMESTAMPTZ,
    last_known_location GEOGRAPHY(POINT, 4326), -- GPS coordinates
    metadata JSONB DEFAULT '{}', -- Device-specific configuration
    current_assigned_to INTEGER REFERENCES users(id), -- Operator currently using device
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create spatial index for location queries
CREATE INDEX idx_devices_location ON devices USING GIST (last_known_location);

-- ==================== DEVICE GROUPS ====================
CREATE TABLE device_groups (
    id SERIAL PRIMARY KEY,
    group_id UUID UNIQUE DEFAULT uuid_generate_v4(),
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    group_name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, group_name)
);

CREATE TABLE device_group_members (
    device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    group_id INTEGER REFERENCES device_groups(id) ON DELETE CASCADE,
    added_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (device_id, group_id)
);

-- ==================== COMMANDS (OTA & Remote Control) ====================
CREATE TABLE commands (
    id SERIAL PRIMARY KEY,
    command_id UUID UNIQUE DEFAULT uuid_generate_v4(),
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    command_type VARCHAR(50) NOT NULL, -- 'reboot', 'calibrate', 'update_firmware', 'collect_data', 'emergency_stop'
    payload JSONB NOT NULL,
    status VARCHAR(20) DEFAULT 'queued', -- 'queued', 'delivered', 'in_progress', 'completed', 'failed', 'cancelled'
    priority INTEGER DEFAULT 1, -- 0=critical, 1=normal, 2=low
    queued_at TIMESTAMPTZ DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    result JSONB,
    error_message TEXT,
    created_by INTEGER REFERENCES users(id),
    retry_count INTEGER DEFAULT 0
);

CREATE INDEX idx_commands_device_status ON commands(device_id, status);
CREATE INDEX idx_commands_queued ON commands(priority, queued_at) WHERE status = 'queued';

-- ==================== AUDIT LOGS ====================
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    log_id UUID DEFAULT uuid_generate_v4(),
    tenant_id INTEGER REFERENCES tenants(id),
    user_id INTEGER REFERENCES users(id),
    device_id INTEGER REFERENCES devices(id),
    action VARCHAR(100) NOT NULL, -- 'user.login', 'device.register', 'command.send', 'config.change'
    resource_type VARCHAR(50), -- 'user', 'device', 'command', 'tenant'
    resource_id VARCHAR(100),
    old_value JSONB,
    new_value JSONB,
    ip_address INET,
    user_agent TEXT,
    status VARCHAR(20), -- 'success', 'failure', 'denied'
    details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Partition audit_logs by month for better performance
CREATE INDEX idx_audit_tenant_time ON audit_logs(tenant_id, created_at DESC);
CREATE INDEX idx_audit_user ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_device ON audit_logs(device_id, created_at DESC);

-- ==================== SESSIONS ====================
CREATE TABLE user_sessions (
    id SERIAL PRIMARY KEY,
    session_id UUID UNIQUE DEFAULT uuid_generate_v4(),
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    ip_address INET,
    user_agent TEXT,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ==================== FUNCTIONS & TRIGGERS ====================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_devices_updated_at BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenants_updated_at BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Row-Level Security (RLS) policies for multi-tenancy
-- These ensure users can only see data from their own tenant
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY tenant_isolation_users ON users
    USING (tenant_id = (SELECT tenant_id FROM users WHERE user_id = current_setting('app.current_user_id')::INT));

CREATE POLICY tenant_isolation_devices ON devices
    USING (tenant_id = (SELECT tenant_id FROM users WHERE user_id = current_setting('app.current_user_id')::INT));

-- Grant permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO current_user;