package com.pranav.authcore.security.provider;

import com.pranav.authcore.dto.AuthResponse;
import com.pranav.authcore.dto.LoginRequest;
import com.pranav.authcore.dto.UserPermissionsDTO;
import com.pranav.authcore.security.token.LoginAuthenticationToken;
import com.pranav.authcore.service.AuthService;
import com.pranav.authcore.service.RbacService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Authentication Provider for Login flow.
 * Validates email/password and returns authenticated token with authorities.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class LoginAuthenticationProvider implements AuthenticationProvider {

    private final AuthService authService;
    private final RbacService rbacService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        LoginAuthenticationToken unauthenticated = (LoginAuthenticationToken) authentication;

        String email = (String) unauthenticated.getPrincipal();
        String password = (String) unauthenticated.getCredentials();

        log.debug("Attempting login for user: {}", email);

        try {
            // Authenticate via AuthService
            LoginRequest loginRequest = new LoginRequest();
            loginRequest.setEmail(email);
            loginRequest.setPassword(password);
            // Note: IP and UserAgent should be set by filter before calling this

            AuthResponse authResponse = authService.login(loginRequest);

            // Load permissions for authorities
            UserPermissionsDTO permissions = rbacService.getUserPermissions(
                authResponse.getUserId(),
                authResponse.getOrgId()
            );

            List<GrantedAuthority> authorities = permissions.getPermissions().stream()
                .map(p -> new SimpleGrantedAuthority(p.getCode()))
                .collect(Collectors.toList());

            // Create authenticated token
            LoginAuthenticationToken authenticated = new LoginAuthenticationToken(
                authResponse.getUserId(),
                authResponse.getEmail(),
                authResponse.getOrgId(),
                authorities,
                authResponse.getRefreshToken()
            );

            log.info("Login successful for user: {}", email);
            return authenticated;

        } catch (Exception e) {
            log.error("Login failed for user: {}", email, e);
            throw new BadCredentialsException("Authentication failed: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return LoginAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
