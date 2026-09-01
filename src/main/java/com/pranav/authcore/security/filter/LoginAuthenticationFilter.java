package com.pranav.authcore.security.filter;

import com.pranav.authcore.dto.LoginRequest;
import com.pranav.authcore.security.token.LoginAuthenticationToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

/**
 * Login Authentication Filter - Handles login at filter level using Spring Security pattern.
 * Uses AuthenticationManager → LoginAuthenticationProvider for validation.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class LoginAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Check if this is a login request
        if (isLoginRequest(request)) {
            handleLogin(request, response);
            return; // Don't continue filter chain
        }

        filterChain.doFilter(request, response);
    }

    private boolean isLoginRequest(HttpServletRequest request) {
        return HttpMethod.POST.matches(request.getMethod()) &&
               request.getRequestURI().endsWith("/api/auth/login");
    }

    private void handleLogin(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            // Parse login request
            LoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);
            
            // Set IP and user agent
            loginRequest.setIpAddress(request.getRemoteAddr());
            loginRequest.setUserAgent(request.getHeader("User-Agent"));

            // Create unauthenticated token
            LoginAuthenticationToken unauthenticated = new LoginAuthenticationToken(
                loginRequest.getEmail(),
                loginRequest.getPassword()
            );

            // Authenticate via AuthenticationManager → LoginAuthenticationProvider
            Authentication authenticated = authenticationManager.authenticate(unauthenticated);
            LoginAuthenticationToken authToken = (LoginAuthenticationToken) authenticated;

            // Set authenticated token in SecurityContext
            SecurityContextHolder.getContext().setAuthentication(authenticated);

            // Set token in Authorization header
            response.setHeader("Authorization", "Bearer " + authToken.getRefreshToken());

            // Return user info in response body (without token)
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_OK);
            
            String jsonResponse = String.format(
                "{\"userId\":\"%s\",\"email\":\"%s\",\"orgId\":%s,\"mfaEnabled\":%b}",
                authToken.getUserId(),
                authToken.getEmail(),
                authToken.getOrgId() != null ? "\"" + authToken.getOrgId() + "\"" : "null",
                false
            );
            response.getWriter().write(jsonResponse);

            log.info("Login successful for user: {}", authToken.getEmail());

        } catch (Exception e) {
            log.error("Login failed", e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"" + e.getMessage() + "\"}");
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Only process login requests in this filter
        return !isLoginRequest(request);
    }
}
