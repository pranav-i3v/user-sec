package com.pranav.authcore.exception;

public class UnauthorizedException extends AuthException {
    public UnauthorizedException(String message) {
        super(message);
    }
}
