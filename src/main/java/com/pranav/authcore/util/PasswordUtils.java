package com.pranav.authcore.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class PasswordUtils {

    private final PasswordEncoder passwordEncoder;

    public PasswordUtils() {
        this.passwordEncoder = new BCryptPasswordEncoder(12); // strength 12
    }

    /**
     * Hashes a plaintext password using BCrypt
     * @param plainPassword plaintext password
     * @return BCrypt hash
     */
    public String hashPassword(String plainPassword) {
        return passwordEncoder.encode(plainPassword);
    }

    /**
     * Verifies a plaintext password against a stored BCrypt hash
     * @param plainPassword plaintext password
     * @param hashedPassword stored BCrypt hash
     * @return true if password matches
     */
    public boolean verifyPassword(String plainPassword, String hashedPassword) {
        return passwordEncoder.matches(plainPassword, hashedPassword);
    }

    /**
     * Checks if password needs rehashing (e.g., due to algorithm upgrade)
     * @param hashedPassword stored hash
     * @return true if password should be rehashed
     */
    public boolean needsRehash(String hashedPassword) {
        return passwordEncoder.upgradeEncoding(hashedPassword);
    }
}
