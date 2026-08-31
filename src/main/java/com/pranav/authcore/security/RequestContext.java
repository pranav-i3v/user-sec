package com.pranav.authcore.security;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.UUID;

/**
 * Thread-local storage for current request context.
 * Provides easy access to authenticated user and organization.
 */
@Data
@AllArgsConstructor
public class RequestContext {

    private UUID userId;
    private String email;
    private UUID orgId;

    private static final ThreadLocal<RequestContext> CONTEXT = new ThreadLocal<>();

    public static void set(RequestContext context) {
        CONTEXT.set(context);
    }

    public static RequestContext get() {
        return CONTEXT.get();
    }

    public static void clear() {
        CONTEXT.remove();
    }

    public static UUID getCurrentUserId() {
        RequestContext ctx = CONTEXT.get();
        return ctx != null ? ctx.getUserId() : null;
    }

    public static UUID getCurrentOrgId() {
        RequestContext ctx = CONTEXT.get();
        return ctx != null ? ctx.getOrgId() : null;
    }

    public static String getCurrentUserEmail() {
        RequestContext ctx = CONTEXT.get();
        return ctx != null ? ctx.getEmail() : null;
    }
}
