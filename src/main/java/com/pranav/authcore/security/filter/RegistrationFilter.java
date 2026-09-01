package com.pranav.authcore.security.filter;

import com.pranav.authcore.dto.RegisterRequest;
import com.pranav.authcore.security.token.RegistrationAuthenticationToken;
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
 * Registration Filter - Handles registration at filter level using Spring Security pattern.
 * Uses AuthenticationManager → RegistrationAuthenticationProvider for validation.
 * Sets token in response header instead of body.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RegistrationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
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

            // Create unauthenticated token
            RegistrationAuthenticationToken unauthenticated = new RegistrationAuthenticationToken(
                registerRequest.getEmail(),
                registerRequest.getPassword(),
                registerRequest.getOrgId()
            );

            // Authenticate via AuthenticationManager → RegistrationAuthenticationProvider
            Authentication authenticated = authenticationManager.authenticate(unauthenticated);
            RegistrationAuthenticationToken authToken = (RegistrationAuthenticationToken) authenticated;

            // Set authenticated token in SecurityContext
            SecurityContextHolder.getContext().setAuthentication(authenticated);

            // Set token in Authorization header
            response.setHeader("Authorization", "Bearer " + authToken.getRefreshToken());

            // Return user info in response body (without token)
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_CREATED);
            
            String jsonResponse = String.format(
                "{\"userId\":\"%s\",\"email\":\"%s\",\"orgId\":%s,\"mfaEnabled\":%b}",
                authToken.getUserId(),
                authToken.getEmail(),
                authToken.getOrgId() != null ? "\"" + authToken.getOrgId() + "\"" : "null",
                false
            );
            response.getWriter().write(jsonResponse);

            log.info("Registration successful for user: {}", authToken.getEmail());

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
