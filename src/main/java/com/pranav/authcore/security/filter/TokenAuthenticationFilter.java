package com.pranav.authcore.security.filter;

import com.pranav.authcore.security.token.BearerTokenAuthenticationToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Token Authentication Filter - validates tokens from Authorization header using Spring Security pattern.
 * Uses AuthenticationManager → BearerTokenAuthenticationProvider for validation.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;

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
        }
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader(AUTHORIZATION_HEADER);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            return header.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    private void authenticateToken(String rawToken) {
        try {
            // Create unauthenticated token
            BearerTokenAuthenticationToken unauthenticated = new BearerTokenAuthenticationToken(rawToken);

            // Authenticate via AuthenticationManager → BearerTokenAuthenticationProvider
            Authentication authenticated = authenticationManager.authenticate(unauthenticated);
            BearerTokenAuthenticationToken authToken = (BearerTokenAuthenticationToken) authenticated;

            // Set Spring Security context
            SecurityContextHolder.getContext().setAuthentication(authenticated);

            // Set RequestContext for easy access in services
            RequestContext.set(new RequestContext(
                authToken.getUserId(),
                authToken.getEmail(),
                authToken.getOrgId()
            ));

            log.debug("Authenticated user: {} for org: {}", authToken.getEmail(), authToken.getOrgId());

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
