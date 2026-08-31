package com.pranav.authcore.security;

import com.pranav.authcore.exception.UnauthorizedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Utility to access authenticated user information from SecurityContext.
 */
@Component
public class SecurityUtils {

    /**
     * Get current authenticated TokenAuthentication
     */
    public static TokenAuthentication getCurrentAuthentication() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof TokenAuthentication) {
            return (TokenAuthentication) auth;
        }
        return null;
    }

    /**
     * Get current user ID (throws exception if not authenticated)
     */
    public static UUID getCurrentUserId() {
        TokenAuthentication auth = getCurrentAuthentication();
        if (auth == null) {
            throw new UnauthorizedException("User not authenticated");
        }
        return auth.getUserId();
    }

    /**
     * Get current organization ID (returns null if no org context)
     */
    public static UUID getCurrentOrgId() {
        TokenAuthentication auth = getCurrentAuthentication();
        return auth != null ? auth.getOrgId() : null;
    }

    /**
     * Get current user email
     */
    public static String getCurrentUserEmail() {
        TokenAuthentication auth = getCurrentAuthentication();
        if (auth == null) {
            throw new UnauthorizedException("User not authenticated");
        }
        return auth.getEmail();
    }

    /**
     * Check if user is authenticated
     */
    public static boolean isAuthenticated() {
        return getCurrentAuthentication() != null;
    }

    /**
     * Check if user has a specific permission
     */
    public static boolean hasPermission(String permission) {
        TokenAuthentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }
        return auth.getPermissions().contains(permission);
    }

    /**
     * Check if user has a specific role
     */
    public static boolean hasRole(String role) {
        TokenAuthentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }
        return auth.getRoles().contains(role);
    }
}
