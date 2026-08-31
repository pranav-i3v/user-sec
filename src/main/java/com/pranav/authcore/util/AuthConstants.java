package com.pranav.authcore.util;

public final class AuthConstants {

    private AuthConstants() {
        throw new UnsupportedOperationException("Utility class");
    }

    // Audit Event Types
    public static final String EVENT_LOGIN_SUCCESS = "LOGIN_SUCCESS";
    public static final String EVENT_LOGIN_FAILED = "LOGIN_FAILED";
    public static final String EVENT_TOKEN_REFRESHED = "TOKEN_REFRESHED";
    public static final String EVENT_TOKEN_REUSE_DETECTED = "TOKEN_REUSE_DETECTED";
    public static final String EVENT_LOGOUT = "LOGOUT";
    public static final String EVENT_ROLE_GRANTED = "ROLE_GRANTED";
    public static final String EVENT_ROLE_REVOKED = "ROLE_REVOKED";
    public static final String EVENT_MFA_ENABLED = "MFA_ENABLED";
    public static final String EVENT_MFA_DISABLED = "MFA_DISABLED";
    public static final String EVENT_ACCOUNT_LOCKED = "ACCOUNT_LOCKED";
    public static final String EVENT_ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED";

    // System Roles
    public static final String ROLE_SUPER_ADMIN = "super_admin";
    public static final String ROLE_ORG_ADMIN = "org_admin";
    public static final String ROLE_ORG_MEMBER = "org_member";
}
