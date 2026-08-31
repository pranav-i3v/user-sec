package com.pranav.authcore.exception;

public class AccountLockedException extends AuthException {
    public AccountLockedException(String message) {
        super(message);
    }
}
