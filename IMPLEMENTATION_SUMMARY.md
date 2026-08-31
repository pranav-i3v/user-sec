# Auth-Server-Core Library - Implementation Summary

## 📦 Complete Implementation

### Project Structure
```
user-sec/
├── pom.xml (Spring Boot 4.1.1, Java 21)
├── README.md (Comprehensive documentation)
├── src/
│   ├── main/
│   │   ├── java/com/pranav/authcore/
│   │   │   ├── entity/               (9 JPA entities)
│   │   │   │   ├── Organization.java
│   │   │   │   ├── User.java
│   │   │   │   ├── OrgMembership.java
│   │   │   │   ├── Role.java
│   │   │   │   ├── Permission.java
│   │   │   │   ├── RolePermission.java
│   │   │   │   ├── UserRole.java
│   │   │   │   ├── RefreshToken.java
│   │   │   │   └── AuthAuditLog.java
│   │   │   │
│   │   │   ├── repository/           (9 Spring Data JPA repositories)
│   │   │   │   ├── OrganizationRepository.java
│   │   │   │   ├── UserRepository.java
│   │   │   │   ├── OrgMembershipRepository.java
│   │   │   │   ├── RoleRepository.java
│   │   │   │   ├── PermissionRepository.java
│   │   │   │   ├── RolePermissionRepository.java
│   │   │   │   ├── UserRoleRepository.java
│   │   │   │   ├── RefreshTokenRepository.java
│   │   │   │   └── AuthAuditLogRepository.java
│   │   │   │
│   │   │   ├── service/              (5 core services)
│   │   │   │   ├── AuthService.java              ✅ Login, token rotation, logout
│   │   │   │   ├── AccountLockoutService.java    ✅ Failed attempts, account locking
│   │   │   │   ├── MfaService.java               ✅ TOTP generation & verification
│   │   │   │   ├── AuditService.java             ✅ Comprehensive audit logging
│   │   │   │   └── RbacService.java              ✅ Permission evaluation
│   │   │   │
│   │   │   ├── dto/                  (4 DTOs)
│   │   │   │   ├── LoginRequest.java
│   │   │   │   ├── RefreshTokenRequest.java
│   │   │   │   ├── AuthResponse.java
│   │   │   │   └── UserPermissionsDTO.java
│   │   │   │
│   │   │   ├── util/                 (4 utilities)
│   │   │   │   ├── TokenUtils.java               ✅ Secure token generation & SHA-256 hashing
│   │   │   │   ├── PasswordUtils.java            ✅ BCrypt password hashing
│   │   │   │   ├── PathMatcher.java              ✅ Ant-style path matching
│   │   │   │   └── AuthConstants.java
│   │   │   │
│   │   │   ├── exception/            (5 exceptions)
│   │   │   │   ├── AuthException.java
│   │   │   │   ├── InvalidCredentialsException.java
│   │   │   │   ├── AccountLockedException.java
│   │   │   │   ├── InvalidTokenException.java
│   │   │   │   └── TokenReuseDetectedException.java
│   │   │   │
│   │   │   ├── config/               (2 configurations)
│   │   │   │   ├── AuthCoreProperties.java
│   │   │   │   └── SecurityConfig.java
│   │   │   │
│   │   │   └── AuthCoreApplication.java
│   │   │
│   │   └── resources/
│   │       ├── application.properties
│   │       └── db/seed.sql (System roles & permissions)
│   │
│   └── test/java/com/pranav/authcore/
│       └── service/AuthServiceTest.java (Unit test examples)
```

## 🎯 Key Features Implemented

### 1. **Authentication Service** (`AuthService`)
- ✅ Email/password login with BCrypt verification
- ✅ Secure token generation (48-byte random tokens)
- ✅ SHA-256 token hashing (never stores plaintext)
- ✅ Refresh token rotation on every use
- ✅ Token family tracking for reuse detection
- ✅ MFA integration (optional TOTP check)
- ✅ Multi-org context resolution
- ✅ Last login timestamp tracking

### 2. **Token Rotation & Security** (`AuthService + RefreshTokenRepository`)
- ✅ **Automatic rotation**: Old token revoked → New token issued
- ✅ **Reuse detection**: If revoked token reused → Revoke entire family
- ✅ **Family tracking**: All rotated tokens share `family_id`
- ✅ **Audit logging**: Token reuse triggers high-severity alert
- ✅ **Expiry tracking**: Configurable TTL (default 30 days)
- ✅ **IP & User-Agent tracking**: Stored with each token

### 3. **Account Lockout** (`AccountLockoutService`)
- ✅ Failed login counter per user
- ✅ Auto-lock after N attempts (default: 5)
- ✅ Timed lockout (default: 30 minutes)
- ✅ Auto-reset on successful login
- ✅ Manual unlock method for admins

### 4. **Multi-Factor Authentication** (`MfaService`)
- ✅ TOTP secret generation
- ✅ QR code generation (Base64 data URI)
- ✅ TOTP code verification
- ✅ Google Authenticator compatible
- ✅ Configurable issuer name

### 5. **RBAC Authorization** (`RbacService`)
- ✅ Path-pattern matching (Ant-style: `/api/orders/**`)
- ✅ HTTP method filtering (GET, POST, ANY, etc.)
- ✅ Multi-tenant permission isolation
- ✅ System-wide + org-specific roles
- ✅ Permission aggregation across roles
- ✅ `hasPermission()` and `hasRole()` checks

### 6. **Audit Logging** (`AuditService`)
Event types tracked:
- `LOGIN_SUCCESS` / `LOGIN_FAILED`
- `TOKEN_REFRESHED`
- `TOKEN_REUSE_DETECTED` ⚠️ (security alert)
- `LOGOUT`
- `ROLE_GRANTED` / `ROLE_REVOKED`
- `MFA_ENABLED` / `MFA_DISABLED`
- `ACCOUNT_LOCKED` / `ACCOUNT_UNLOCKED`

Each log includes:
- User ID, Organization ID
- Event type
- Metadata (JSON)
- IP address, User-Agent
- Timestamp

## 🔧 Utilities

### TokenUtils
- `generateSecureToken()` → 48-byte random token (Base64-encoded)
- `hashToken(token)` → SHA-256 hash (hex-encoded)
- `verifyToken(token, hash)` → Constant-time comparison

### PasswordUtils
- `hashPassword(plaintext)` → BCrypt hash (strength 12)
- `verifyPassword(plaintext, hash)` → BCrypt verification
- `needsRehash(hash)` → Check if upgrade needed

### PathMatcher
- `matches(pattern, path)` → Ant-style matching
- `matchesMethod(required, actual)` → HTTP method check

## 📊 Database Schema (9 Tables)

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `organizations` | Tenants | id, name, slug, status |
| `users` | Global identity | email, password_hash, mfa_enabled, locked_until |
| `org_memberships` | User ↔ Org links | user_id, org_id, status |
| `roles` | RBAC roles | name, org_id (NULL = system), is_system |
| `permissions` | API patterns | path_pattern, http_method, code |
| `role_permissions` | Role → Permission | role_id, permission_id |
| `user_roles` | User → Role (per org) | org_membership_id, role_id |
| `refresh_tokens` | Hashed tokens | token_hash, family_id, revoked_at, revoked_reason |
| `auth_audit_log` | Security events | event_type, metadata, ip_address |

## 🔐 Security Features

1. **No plaintext tokens**: SHA-256 hashing for all refresh tokens
2. **Token rotation**: Every refresh generates new token + revokes old
3. **Replay protection**: Reused tokens → family revocation
4. **Account lockout**: Auto-lock after failed attempts
5. **MFA support**: TOTP for sensitive accounts
6. **Audit trail**: Complete event logging
7. **BCrypt passwords**: Industry-standard hashing
8. **Constant-time comparison**: Prevents timing attacks

## 📝 Configuration Properties

```properties
# Token expiry (hours)
auth.refresh-token.expiry-hours=720

# Account lockout
auth.lockout.max-attempts=5
auth.lockout.duration-minutes=30

# MFA issuer name
auth.mfa.issuer=YourAppName
```

## 🧪 Testing

Sample unit test provided in `AuthServiceTest.java`:
- ✅ Successful login
- ✅ Invalid password handling
- ✅ User not found handling
- ✅ MFA required flow
- Uses Mockito for service mocking

## 📦 Dependencies

- Spring Boot 4.1.1 (Java 21)
- Spring Data JPA
- Spring Security
- PostgreSQL Driver
- Lombok
- TOTP library (dev.samstevens.totp)
- Hibernate 6.x

## 🚀 Next Steps

1. **Set JAVA_HOME** environment variable
2. **Run DDL** (provided in project docs)
3. **Run seed SQL** (`src/main/resources/db/seed.sql`)
4. **Configure database** in `application.properties`
5. **Build**: `mvn clean install`
6. **Use in Auth Service**: Inject services in controllers

## 📖 Usage Example

```java
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final RbacService rbacService;

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @PostMapping("/refresh")
    public AuthResponse refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.refreshToken(request);
    }

    @GetMapping("/check-permission")
    public boolean checkPermission(
        @RequestParam UUID userId,
        @RequestParam UUID orgId,
        @RequestParam String path,
        @RequestParam String method) {
        return rbacService.hasPermission(userId, orgId, path, method);
    }
}
```

## ✅ Deliverables

- [x] 9 JPA entity classes
- [x] 9 Spring Data repositories with custom queries
- [x] 5 service classes (Auth, RBAC, MFA, Lockout, Audit)
- [x] 4 utility classes (Token, Password, PathMatcher, Constants)
- [x] 5 exception classes
- [x] 4 DTO classes
- [x] 2 configuration classes
- [x] Sample unit tests
- [x] Seed SQL script
- [x] Comprehensive README.md
- [x] Complete pom.xml with dependencies

## 📌 Notes

- **PostgreSQL extensions required**: `pgcrypto`, `citext`
- **Token security**: Only Auth Service has write access to `refresh_tokens`
- **Multi-tenant**: User can belong to multiple orgs
- **Roles**: Can be system-wide (shared) or org-specific
- **Permissions**: Ant-style patterns support wildcards (`/api/orders/**`)

---

**Status**: ✅ Complete - Ready for integration into Auth Service
