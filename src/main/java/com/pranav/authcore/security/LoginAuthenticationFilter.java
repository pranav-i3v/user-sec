package com.pranav.authcore.security;

import com.pranav.authcore.dto.AuthResponse;
import com.pranav.authcore.dto.LoginRequest;
import com.pranav.authcore.service.AuthService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

/**
 * Login Authentication Filter - Handles login at filter level.
 * Sets token in response header instead of body.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class LoginAuthenticationFilter extends OncePerRequestFilter {

    private final AuthService authService;
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

            // Authenticate and generate token
            AuthResponse authResponse = authService.login(loginRequest);

            // Set token in Authorization header
            response.setHeader("Authorization", "Bearer " + authResponse.getRefreshToken());

            // Return user info in response body (without token)
            authResponse.setRefreshToken(null); // Don't send token in body
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_OK);
            objectMapper.writeValue(response.getOutputStream(), authResponse);

            log.debug("Login successful for user: {}", authResponse.getEmail());

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
