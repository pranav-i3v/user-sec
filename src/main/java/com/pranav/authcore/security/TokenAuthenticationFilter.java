package com.pranav.authcore.security;

import com.pranav.authcore.dto.UserPermissionsDTO;
import com.pranav.authcore.entity.RefreshToken;
import com.pranav.authcore.entity.User;
import com.pranav.authcore.repository.RefreshTokenRepository;
import com.pranav.authcore.repository.UserRepository;
import com.pranav.authcore.service.RbacService;
import com.pranav.authcore.util.TokenUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Token Authentication Filter - validates tokens from Authorization header.
 * 
 * Flow:
 * 1. Extract token from "Authorization: Bearer <token>" header
 * 2. Hash token and lookup in database
 * 3. Validate token (not revoked, not expired)
 * 4. Load user permissions for user+org context
 * 5. Set SecurityContext with TokenAuthentication
 * 6. Set RequestContext for easy access
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final RefreshTokenRepository refreshTokenRepository;
    private final RbacService rbacService;
    private final TokenUtils tokenUtils;

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                     HttpServletResponse response, 
                                     FilterChain filterChain) throws ServletException, IOException {
        try {
            String token = extractToken(request);
            
            if (token != null) {
                authenticateToken(token);
            }
            
            filterChain.doFilter(request, response);
        } finally {
            // Clean up ThreadLocal to prevent memory leaks
            RequestContext.clear();
            SecurityContextHolder.clearContext();
        }
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader(AUTHORIZATION_HEADER);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            return header.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    private void authenticateToken(String token) {
        try {
            // Hash token and lookup in database
            String tokenHash = tokenUtils.hashToken(token);
            Optional<RefreshToken> tokenOpt = refreshTokenRepository.findByTokenHash(tokenHash);

            if (tokenOpt.isEmpty()) {
                log.debug("Token not found in database");
                return;
            }

            RefreshToken refreshToken = tokenOpt.get();

            // Validate token
            if (refreshToken.getRevokedAt() != null) {
                log.warn("Attempt to use revoked token: {}", refreshToken.getId());
                return;
            }

            if (refreshToken.getExpiresAt().isBefore(Instant.now())) {
                log.debug("Token expired: {}", refreshToken.getId());
                return;
            }

            User user = refreshToken.getUser();

            if (user.getDeletedAt() != null || user.getStatus() != User.UserStatus.ACTIVE) {
                log.warn("Token belongs to inactive user: {}", user.getId());
                return;
            }

            // Load permissions for user+org context
            UserPermissionsDTO permissions = rbacService.getUserPermissions(
                user.getId(), 
                refreshToken.getOrganization() != null ? refreshToken.getOrganization().getId() : null
            );

            List<String> permissionCodes = permissions.getPermissions().stream()
                .map(UserPermissionsDTO.PermissionDTO::getCode)
                .collect(Collectors.toList());

            List<String> roles = permissions.getRoles();

            // Create authentication object
            TokenAuthentication authentication = new TokenAuthentication(
                user.getId(),
                user.getEmail(),
                refreshToken.getOrganization() != null ? refreshToken.getOrganization().getId() : null,
                permissionCodes,
                roles
            );

            // Set Spring Security context
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Set RequestContext for easy access in services
            RequestContext.set(new RequestContext(
                user.getId(),
                user.getEmail(),
                refreshToken.getOrganization() != null ? refreshToken.getOrganization().getId() : null
            ));

            log.debug("Authenticated user: {} for org: {}", user.getEmail(), 
                refreshToken.getOrganization() != null ? refreshToken.getOrganization().getSlug() : "none");

        } catch (Exception e) {
            log.error("Token authentication failed", e);
            SecurityContextHolder.clearContext();
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Skip authentication for public endpoints
        String path = request.getRequestURI();
        return path.startsWith("/api/auth/login") ||
               path.startsWith("/api/auth/refresh") ||
               path.startsWith("/api/auth/register") ||
               path.startsWith("/actuator/health") ||
               path.startsWith("/public/");
    }
}
