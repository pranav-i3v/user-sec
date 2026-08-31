# Auth-Server-Core Library

A production-grade Spring Boot **auto-configured** authentication and authorization library for multi-tenant RBAC systems with refresh token rotation and comprehensive security features.

> **⚡ Zero Configuration Required** - Just add the dependency and all services are automatically available for injection!

## Features

### Authentication
- ✅ **User Registration** with automatic "member" role assignment
- ✅ Email/Password login with BCrypt hashing
- ✅ Secure refresh token rotation with replay attack detection
- ✅ Token family tracking for reuse detection
- ✅ Account lockout after failed attempts
- ✅ TOTP-based Multi-Factor Authentication (MFA)

### Authorization
- ✅ Role-Based Access Control (RBAC)
- ✅ Path-pattern permissions (Ant-style matching)
- ✅ HTTP method-based permissions
- ✅ Multi-tenant organization support
- ✅ System-wide and org-specific roles

### Security
- ✅ SHA-256 token hashing (tokens never stored in plaintext)
- ✅ Refresh token rotation on every use
- ✅ Token reuse detection with family revocation
- ✅ Failed login tracking and account lockout
- ✅ Comprehensive audit logging
- ✅ **Spring Security Filter Integration** - Automatic token validation on every request
- ✅ **SecurityContext population** - User/org context auto-injected
- ✅ **Method security** - `@PreAuthorize` and custom annotations

## Architecture

### Entities (9 Tables)
1. **organizations** - Tenant definitions
2. **users** - Global user identity
3. **org_memberships** - User-Organization relationships
4. **roles** - RBAC roles (system or org-specific)
5. **permissions** - API path patterns + HTTP methods
6. **role_permissions** - Role-Permission mapping
7. **user_roles** - User role assignments within orgs
8. **refresh_tokens** - Hashed tokens with rotation tracking
9. **auth_audit_log** - Security audit trail

## Usage

> **⚡ This library is auto-configured!** Just add the dependency and all beans are automatically available. No manual configuration needed.

### 1. Build the Library

```bash
cd user-sec
mvnw clean install
```

### 2. Add Dependency to Your Auth Service

```xml
<dependency>
    <groupId>com.pranav</groupId>
    <artifactId>user-sec</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

### 3. Configure Database

```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/auth_db
spring.datasource.username=postgres
spring.datasource.password=postgres

auth.refresh-token.expiry-hours=720      # 30 days
auth.lockout.max-attempts=5
auth.lockout.duration-minutes=30
auth.mfa.issuer=YourAppName
```

### 4. Run DDL Script

Execute the PostgreSQL DDL (see project documentation) to create all tables.

### 5. Use Services in Your Auth Controller (Auto-Injected)

```java
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RbacService rbacService;
    private final MfaService mfaService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        AuthResponse response = authService.register(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        AuthResponse response = authService.refreshToken(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody LogoutRequest request) {
        authService.logout(request.getRefreshToken());
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/permissions")
    public ResponseEntity<UserPermissionsDTO> getPermissions(
            @RequestParam UUID userId,
            @RequestParam UUID orgId) {
        UserPermissionsDTO permissions = rbacService.getUserPermissions(userId, orgId);
        return ResponseEntity.ok(permissions);
    }
}
```

### 5. RBAC Example

```java
// Check if user has permission
boolean hasAccess = rbacService.hasPermission(
    userId, 
    orgId, 
    "/api/orders/123", 
    "GET"
);

// Check if user has a specific role
boolean isAdmin = rbacService.hasRole(userId, orgId, "admin");
```

### 6. Accessing Authenticated User (In Your Microservice)

The filter automatically populates SecurityContext. Access authenticated user anywhere:

```java
import com.pranav.authcore.security.SecurityUtils;
import com.pranav.authcore.security.RequestContext;

@RestController
@RequiredArgsConstructor
public class OrderController {

    private final OrderService orderService;

    @GetMapping("/api/orders")
    public List<Order> getMyOrders() {
        // Get current authenticated user ID
        UUID userId = SecurityUtils.getCurrentUserId();
        UUID orgId = SecurityUtils.getCurrentOrgId();
        
        return orderService.getOrdersForUser(userId, orgId);
    }

    // Using RequestContext (alternative)
    @PostMapping("/api/orders")
    public Order createOrder(@RequestBody OrderRequest request) {
        UUID userId = RequestContext.getCurrentUserId();
        return orderService.createOrder(userId, request);
    }

    // Using @PreAuthorize for method security
    @PreAuthorize("hasAuthority('orders:delete')")
    @DeleteMapping("/api/orders/{id}")
    public void deleteOrder(@PathVariable UUID id) {
        orderService.delete(id);
    }
}
```

### 7. Making Authenticated Requests

**Login/Registration Flow:**

```bash
# Step 1: Login - Token returned in response header
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "SecureP@ss123"}' \
  -i

# Response:
# HTTP/1.1 200 OK
# Authorization: Bearer eyJhbGc...
# Content-Type: application/json
# 
# {"userId": "...", "email": "user@example.com", "orgId": "..."}

# Step 2: Extract token from Authorization header and use for subsequent requests
curl -H "Authorization: Bearer eyJhbGc..." \
     http://localhost:8080/api/orders
```

**Key Points:**
- ✅ Login/Register requests processed by **filter** (not controller)
- ✅ Token returned in **Authorization response header** (not body)
- ✅ Client extracts token from header
- ✅ Client includes token in subsequent request headers
- ✅ Professional approach - consistent with UsernamePasswordAuthenticationFilter pattern

The filter will:
1. ✅ Extract and validate token
2. ✅ Check expiration and revocation status
3. ✅ Load user permissions
4. ✅ Populate SecurityContext
5. ✅ Allow/deny request based on permissions

## Service Layer

### AuthService
- `register(RegisterRequest)` - Register new user with automatic "member" role assignment
- `login(LoginRequest)` - Authenticate user, generate refresh token
- `refreshToken(RefreshTokenRequest)` - Rotate token, detect reuse
- `logout(String refreshToken)` - Revoke token
- `revokeAllUserTokens(UUID userId)` - Admin revocation

### RbacService
- `getUserPermissions(UUID userId, UUID orgId)` - Get all permissions
- `hasPermission(userId, orgId, path, method)` - Check access
- `hasRole(userId, orgId, roleName)` - Check role membership

### AccountLockoutService
- `checkAccountLocked(User)` - Throws exception if locked
- `recordFailedLogin(User)` - Increment counter, lock if threshold hit
- `resetFailedLogins(User)` - Clear on successful login
- `unlockAccount(User)` - Admin unlock

### MfaService
- `generateMfaSecret()` - Create TOTP secret
- `generateQrCodeDataUri(User, secret)` - Generate QR for setup
- `verifyMfaCode(User, code)` - Validate TOTP code

### AuditService
- `logSuccessfulLogin(User, Organization, ip, userAgent)`
- `logFailedLogin(User, ip, userAgent)`
- `logTokenRefresh(User, Organization)`
- `logTokenReuseDetected(User, Organization, ip)` - Security event
- `logLogout(User, Organization)`
- `logRoleGranted/Revoked(User, Organization, role, actor)`

## Security Model

### Token Flow

1. **Login**: Generate refresh token → hash with SHA-256 → store hash + family_id
2. **Refresh**: 
   - Verify token hash
   - Check if revoked (reuse detection)
   - Generate new token
   - Revoke old token (mark as ROTATED)
   - Return new token
3. **Reuse Detection**: If a revoked token is presented, revoke entire family

### Account Lockout

- Failed login increments `failed_login_attempts`
- After 5 attempts (configurable), account locked for 30 minutes
- Successful login resets counter
- Audit log tracks all attempts

### MFA

- TOTP (Time-based One-Time Password) using Google Authenticator compatible
- Secret stored encrypted at application layer
- QR code generation for easy setup

## Customization

### Configure Token Expiry

```properties
auth.refresh-token.expiry-hours=168  # 7 days
```

### Configure Account Lockout

```properties
auth.lockout.max-attempts=3
auth.lockout.duration-minutes=60
```

### Configure MFA Issuer

```properties
auth.mfa.issuer=MyCompany
```

## Database Schema Notes

- **citext extension** required for case-insensitive emails
- **pgcrypto extension** for UUID generation
- **Indexes** on:
  - `users.email`
  - `org_memberships(user_id, org_id)`
  - `refresh_tokens(user_id, family_id, token_hash)`
  - `permissions.path_pattern`
  - Audit log: `user_id`, `org_id`, `event_type`

## Auto-Configuration

This library uses Spring Boot auto-configuration (`@AutoConfiguration`) and is automatically discovered when added as a dependency.

**What gets auto-registered:**
- ✅ All 5 services (`AuthService`, `RbacService`, `MfaService`, `AccountLockoutService`, `AuditService`)
- ✅ All 9 repositories
- ✅ All 9 JPA entities
- ✅ All 4 utility beans (`TokenUtils`, `PasswordUtils`, `PathMatcher`, `AuthConstants`)
- ✅ Security configuration (`PasswordEncoder` bean)
- ✅ **LoginAuthenticationFilter** - Handles login at filter level, returns token in header
- ✅ **RegistrationFilter** - Handles registration at filter level, returns token in header
- ✅ **TokenAuthenticationFilter** - Validates tokens on protected requests
- ✅ **Spring Security Filter Chain** - Configured with stateless session management
- ✅ Configuration properties (`AuthCoreProperties`)

**Security Features Enabled:**
- 🔒 **Professional Filter-Based Auth** - Login/Registration handled at filter level (like UsernamePasswordAuthenticationFilter)
- 🔒 **Token in Response Header** - `Authorization: Bearer <token>` returned in response header (not body)
- 🔒 All protected requests require valid token in `Authorization: Bearer <token>` header
- 🔒 Token validation: checks expiration, revocation status, user status
- 🔒 SecurityContext automatically populated with user/org/permissions
- 🔒 Method security enabled: Use `@PreAuthorize("hasAuthority('permission:code')")`
- 🔒 Public endpoints: `/api/auth/login`, `/api/auth/refresh`, `/api/auth/register`, `/actuator/health`, `/public/**`

**Your Auth Service only needs:**
```java
@SpringBootApplication
public class AuthServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}
```

Then inject any service:
```java
@RestController
@RequiredArgsConstructor
public class MyController {
    private final AuthService authService; // Auto-injected!
}
```

## Production Checklist

- [ ] Run DDL with proper database user
- [ ] Create indexes (included in DDL)
- [ ] Configure connection pooling (HikariCP)
- [ ] Enable SSL for PostgreSQL connection
- [ ] Set strong BCrypt strength (12+ rounds)
- [ ] Encrypt MFA secrets at application layer
- [ ] Monitor audit logs for security events
- [ ] Set up alerting for `TOKEN_REUSE_DETECTED` events
- [ ] Implement rate limiting on login endpoints
- [ ] Use HTTPS for all auth endpoints

## License

Proprietary - Internal Use Only

## Authors

Pranav - Senior Spring Boot Developer
