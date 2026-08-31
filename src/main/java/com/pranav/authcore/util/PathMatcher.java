package com.pranav.authcore.util;

import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

@Component
public class PathMatcher {

    private final AntPathMatcher antPathMatcher;

    public PathMatcher() {
        this.antPathMatcher = new AntPathMatcher();
    }

    /**
     * Checks if a request path matches the given pattern (Ant-style)
     * @param pattern Ant-style pattern (e.g., /api/orders/**)
     * @param path actual request path
     * @return true if path matches pattern
     */
    public boolean matches(String pattern, String path) {
        return antPathMatcher.match(pattern, path);
    }

    /**
     * Checks if HTTP method matches
     * @param requiredMethod required method from permission (GET, POST, ANY, etc.)
     * @param actualMethod actual HTTP method from request
     * @return true if methods match
     */
    public boolean matchesMethod(String requiredMethod, String actualMethod) {
        return "ANY".equalsIgnoreCase(requiredMethod) || 
               requiredMethod.equalsIgnoreCase(actualMethod);
    }
}
