package com.pranav.authcore.exception;

public class TokenReuseDetectedException extends AuthException {
    public TokenReuseDetectedException(String message) {
        super(message);
    }
}
