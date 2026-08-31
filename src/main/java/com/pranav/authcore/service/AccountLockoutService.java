package com.pranav.authcore.service;

import com.pranav.authcore.entity.User;
import com.pranav.authcore.exception.AccountLockedException;
import com.pranav.authcore.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AccountLockoutService {

    private final UserRepository userRepository;

    @Value("${auth.lockout.max-attempts:5}")
    private int maxFailedAttempts;

    @Value("${auth.lockout.duration-minutes:30}")
    private int lockoutDurationMinutes;

    /**
     * Checks if account is currently locked
     */
    public void checkAccountLocked(User user) {
        if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(Instant.now())) {
            throw new AccountLockedException(
                String.format("Account is locked until %s", user.getLockedUntil())
            );
        }
    }

    /**
     * Records a failed login attempt and locks account if threshold exceeded
     */
    @Transactional
    public void recordFailedLogin(User user) {
        short attempts = (short) (user.getFailedLoginAttempts() + 1);
        user.setFailedLoginAttempts(attempts);

        if (attempts >= maxFailedAttempts) {
            user.setLockedUntil(Instant.now().plus(Duration.ofMinutes(lockoutDurationMinutes)));
        }

        userRepository.save(user);
    }

    /**
     * Resets failed login attempts on successful authentication
     */
    @Transactional
    public void resetFailedLogins(User user) {
        if (user.getFailedLoginAttempts() > 0 || user.getLockedUntil() != null) {
            user.setFailedLoginAttempts((short) 0);
            user.setLockedUntil(null);
            userRepository.save(user);
        }
    }

    /**
     * Manually unlock a user account (admin operation)
     */
    @Transactional
    public void unlockAccount(User user) {
        user.setFailedLoginAttempts((short) 0);
        user.setLockedUntil(null);
        userRepository.save(user);
    }
}
