-- =====================================================================
-- SEED DATA FOR AUTH-SERVER-CORE
-- =====================================================================

-- Insert system permissions
INSERT INTO permissions (id, code, path_pattern, http_method, description) VALUES
    (gen_random_uuid(), 'users:read', '/api/users/**', 'GET', 'Read user data'),
    (gen_random_uuid(), 'users:write', '/api/users/**', 'POST', 'Create users'),
    (gen_random_uuid(), 'users:update', '/api/users/**', 'PUT', 'Update users'),
    (gen_random_uuid(), 'users:delete', '/api/users/**', 'DELETE', 'Delete users'),
    (gen_random_uuid(), 'orders:read', '/api/orders/**', 'GET', 'Read orders'),
    (gen_random_uuid(), 'orders:write', '/api/orders/**', 'POST', 'Create orders'),
    (gen_random_uuid(), 'inventory:read', '/api/inventory/**', 'GET', 'Read inventory'),
    (gen_random_uuid(), 'admin:all', '/api/admin/**', 'ANY', 'Full admin access');

-- Insert system roles (org_id = NULL means system-wide)
INSERT INTO roles (id, org_id, name, description, is_system) VALUES
    (gen_random_uuid(), NULL, 'super_admin', 'Super Administrator - Full System Access', true),
    (gen_random_uuid(), NULL, 'org_admin', 'Organization Administrator', true),
    (gen_random_uuid(), NULL, 'org_member', 'Organization Member', true);

-- Assign permissions to super_admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'super_admin';

-- Assign basic permissions to org_member role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'org_member'
  AND p.code IN ('users:read', 'orders:read', 'inventory:read');

-- Assign more permissions to org_admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'org_admin'
  AND p.code IN ('users:read', 'users:write', 'users:update', 'orders:read', 'orders:write', 'inventory:read');

-- Example: Create a test organization
-- INSERT INTO organizations (id, name, slug, status) VALUES
--     (gen_random_uuid(), 'Demo Corp', 'demo-corp', 'active');

-- Example: Create a test user (password: 'password123')
-- BCrypt hash for 'password123': $2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyB3Qr4W8Cci
-- INSERT INTO users (id, email, password_hash, status, email_verified_at) VALUES
--     (gen_random_uuid(), 'admin@example.com', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyB3Qr4W8Cci', 'active', now());
