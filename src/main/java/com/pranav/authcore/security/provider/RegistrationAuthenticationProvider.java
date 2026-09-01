package com.pranav.authcore.security.provider;

import com.pranav.authcore.dto.AuthResponse;
import com.pranav.authcore.dto.RegisterRequest;
import com.pranav.authcore.dto.UserPermissionsDTO;
import com.pranav.authcore.security.token.RegistrationAuthenticationToken;
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
 * Authentication Provider for Registration flow.
 * Creates new user and returns authenticated token with authorities.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RegistrationAuthenticationProvider implements AuthenticationProvider {

    private final AuthService authService;
    private final RbacService rbacService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        RegistrationAuthenticationToken unauthenticated = (RegistrationAuthenticationToken) authentication;

        String email = (String) unauthenticated.getEmail();
        String password = (String) unauthenticated.getCredentials();

        log.debug("Attempting registration for user: {}", email);

        try {
            // Register via AuthService
            RegisterRequest registerRequest = new RegisterRequest();
            registerRequest.setEmail(email);
            registerRequest.setPassword(password);
            registerRequest.setOrgId(unauthenticated.getOrgId());
            // Note: IP and UserAgent should be set by filter before calling this

            AuthResponse authResponse = authService.register(registerRequest);

            // Load permissions for authorities (if org provided)
            List<GrantedAuthority> authorities;
            if (authResponse.getOrgId() != null) {
                UserPermissionsDTO permissions = rbacService.getUserPermissions(
                    authResponse.getUserId(),
                    authResponse.getOrgId()
                );
                authorities = permissions.getPermissions().stream()
                    .map(p -> new SimpleGrantedAuthority(p.getCode()))
                    .collect(Collectors.toList());
            } else {
                authorities = List.of(); // No org = no permissions
            }

            // Create authenticated token
            RegistrationAuthenticationToken authenticated = new RegistrationAuthenticationToken(
                authResponse.getUserId(),
                authResponse.getEmail(),
                authResponse.getOrgId(),
                authorities,
                authResponse.getRefreshToken()
            );

            log.info("Registration successful for user: {}", email);
            return authenticated;

        } catch (Exception e) {
            log.error("Registration failed for user: {}", email, e);
            throw new BadCredentialsException("Registration failed: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return RegistrationAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
