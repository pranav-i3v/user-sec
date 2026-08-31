package com.pranav.authcore.security;

import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Custom Authentication object for token-based authentication.
 * Holds user, organization context, and permissions.
 */
@Getter
public class TokenAuthentication implements Authentication {

    private final UUID userId;
    private final String email;
    private final UUID orgId;
    private final List<String> permissions;
    private final List<String> roles;
    private boolean authenticated;

    public TokenAuthentication(UUID userId, String email, UUID orgId, 
                               List<String> permissions, List<String> roles) {
        this.userId = userId;
        this.email = email;
        this.orgId = orgId;
        this.permissions = permissions;
        this.roles = roles;
        this.authenticated = true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return permissions.stream()
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());
    }

    @Override
    public Object getCredentials() {
        return null; // Token already validated
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return email;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.authenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return email;
    }
}
