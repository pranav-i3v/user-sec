package com.pranav.authcore.security.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;
import java.util.UUID;

/**
 * Custom Authentication Token for Bearer Token validation flow.
 * 
 * Unauthenticated: BearerTokenAuthenticationToken(rawToken)
 * Authenticated: BearerTokenAuthenticationToken(userId, email, orgId, authorities)
 */
public class BearerTokenAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;  // rawToken (unauthenticated) or userId (authenticated)
    private UUID orgId;
    private String email;

    /**
     * Unauthenticated constructor - used before token validation
     */
    public BearerTokenAuthenticationToken(String rawToken) {
        super(Collections.emptyList());
        this.principal = rawToken;
        setAuthenticated(false);
    }

    /**
     * Authenticated constructor - used after successful token validation
     */
    public BearerTokenAuthenticationToken(UUID userId, String email, UUID orgId,
                                         Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = userId;
        this.email = email;
        this.orgId = orgId;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null; // No credentials for bearer token
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    public UUID getUserId() {
        return principal instanceof UUID ? (UUID) principal : null;
    }

    public String getRawToken() {
        return principal instanceof String ? (String) principal : null;
    }

    public String getEmail() {
        return email;
    }

    public UUID getOrgId() {
        return orgId;
    }
}
