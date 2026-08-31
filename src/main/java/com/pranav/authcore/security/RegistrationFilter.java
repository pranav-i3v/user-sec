package com.pranav.authcore.security;

import com.pranav.authcore.dto.AuthResponse;
import com.pranav.authcore.dto.RegisterRequest;
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
 * Registration Filter - Handles registration at filter level.
 * Sets token in response header instead of body.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RegistrationFilter extends OncePerRequestFilter {

    private final AuthService authService;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Check if this is a registration request
        if (isRegisterRequest(request)) {
            handleRegistration(request, response);
            return; // Don't continue filter chain
        }

        filterChain.doFilter(request, response);
    }

    private boolean isRegisterRequest(HttpServletRequest request) {
        return HttpMethod.POST.matches(request.getMethod()) &&
               request.getRequestURI().endsWith("/api/auth/register");
    }

    private void handleRegistration(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            // Parse registration request
            RegisterRequest registerRequest = objectMapper.readValue(request.getInputStream(), RegisterRequest.class);
            
            // Set IP and user agent from request
            registerRequest.setIpAddress(request.getRemoteAddr());
            registerRequest.setUserAgent(request.getHeader("User-Agent"));

            // Register and generate token
            AuthResponse authResponse = authService.register(registerRequest);

            // Set token in Authorization header
            response.setHeader("Authorization", "Bearer " + authResponse.getRefreshToken());

            // Return user info in response body (without token)
            authResponse.setRefreshToken(null); // Don't send token in body
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_CREATED);
            objectMapper.writeValue(response.getOutputStream(), authResponse);

            log.debug("Registration successful for user: {}", authResponse.getEmail());

        } catch (Exception e) {
            log.error("Registration failed", e);
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"" + e.getMessage() + "\"}");
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Only process registration requests in this filter
        return !isRegisterRequest(request);
    }
}
