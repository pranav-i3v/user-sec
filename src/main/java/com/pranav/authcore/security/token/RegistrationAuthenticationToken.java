package com.pranav.authcore.security.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;
import java.util.UUID;

/**
 * Custom Authentication Token for Registration flow.
 * 
 * Unauthenticated: RegistrationAuthenticationToken(email, password, orgId)
 * Authenticated: RegistrationAuthenticationToken(userId, email, orgId, authorities, refreshToken)
 */
public class RegistrationAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;  // email (unauthenticated) or userId (authenticated)
    private Object credentials;      // password (cleared after auth)
    private UUID orgId;
    private String email;
    private String refreshToken;     // Set after successful registration

    /**
     * Unauthenticated constructor - used before registration
     */
    public RegistrationAuthenticationToken(String email, String password, UUID orgId) {
        super(Collections.emptyList());
        this.principal = email;
        this.credentials = password;
        this.email = email;
        this.orgId = orgId;
        setAuthenticated(false);
    }

    /**
     * Authenticated constructor - used after successful registration
     */
    public RegistrationAuthenticationToken(UUID userId, String email, UUID orgId,
                                          Collection<? extends GrantedAuthority> authorities,
                                          String refreshToken) {
        super(authorities);
        this.principal = userId;
        this.email = email;
        this.orgId = orgId;
        this.refreshToken = refreshToken;
        this.credentials = null; // Clear credentials for security
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    public UUID getUserId() {
        return principal instanceof UUID ? (UUID) principal : null;
    }

    public String getEmail() {
        return email;
    }

    public UUID getOrgId() {
        return orgId;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.credentials = null;
    }
}
