package com.pranav.authcore.security.provider;

import com.pranav.authcore.dto.UserPermissionsDTO;
import com.pranav.authcore.entity.RefreshToken;
import com.pranav.authcore.entity.User;
import com.pranav.authcore.repository.RefreshTokenRepository;
import com.pranav.authcore.security.token.BearerTokenAuthenticationToken;
import com.pranav.authcore.service.RbacService;
import com.pranav.authcore.util.TokenUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Authentication Provider for Bearer Token validation.
 * Validates refresh token from Authorization header and returns authenticated token.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class BearerTokenAuthenticationProvider implements AuthenticationProvider {

    private final RefreshTokenRepository refreshTokenRepository;
    private final RbacService rbacService;
    private final TokenUtils tokenUtils;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        BearerTokenAuthenticationToken unauthenticated = (BearerTokenAuthenticationToken) authentication;

        String rawToken = unauthenticated.getRawToken();

        log.debug("Attempting bearer token validation");

        try {
            // Hash token and lookup in database
            String tokenHash = tokenUtils.hashToken(rawToken);
            Optional<RefreshToken> tokenOpt = refreshTokenRepository.findByTokenHash(tokenHash);

            if (tokenOpt.isEmpty()) {
                throw new BadCredentialsException("Invalid token");
            }

            RefreshToken refreshToken = tokenOpt.get();

            // Validate token
            if (refreshToken.getRevokedAt() != null) {
                log.warn("Attempt to use revoked token: {}", refreshToken.getId());
                throw new BadCredentialsException("Token has been revoked");
            }

            if (refreshToken.getExpiresAt().isBefore(Instant.now())) {
                log.debug("Token expired: {}", refreshToken.getId());
                throw new BadCredentialsException("Token has expired");
            }

            User user = refreshToken.getUser();

            if (user.getDeletedAt() != null || user.getStatus() != User.UserStatus.ACTIVE) {
                log.warn("Token belongs to inactive user: {}", user.getId());
                throw new BadCredentialsException("User account is not active");
            }

            // Load permissions for user+org context
            UserPermissionsDTO permissions = rbacService.getUserPermissions(
                user.getId(),
                refreshToken.getOrganization() != null ? refreshToken.getOrganization().getId() : null
            );

            List<GrantedAuthority> authorities = permissions.getPermissions().stream()
                .map(p -> new SimpleGrantedAuthority(p.getCode()))
                .collect(Collectors.toList());

            // Create authenticated token
            BearerTokenAuthenticationToken authenticated = new BearerTokenAuthenticationToken(
                user.getId(),
                user.getEmail(),
                refreshToken.getOrganization() != null ? refreshToken.getOrganization().getId() : null,
                authorities
            );

            log.debug("Token validated for user: {}", user.getEmail());
            return authenticated;

        } catch (BadCredentialsException e) {
            throw e;
        } catch (Exception e) {
            log.error("Token validation failed", e);
            throw new BadCredentialsException("Token validation failed: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
