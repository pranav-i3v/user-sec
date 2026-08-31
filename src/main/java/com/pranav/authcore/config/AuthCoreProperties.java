package com.pranav.authcore.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "auth")
@Data
public class AuthCoreProperties {

    private RefreshToken refreshToken = new RefreshToken();
    private Lockout lockout = new Lockout();
    private Mfa mfa = new Mfa();

    @Data
    public static class RefreshToken {
        private int expiryHours = 720; // 30 days
    }

    @Data
    public static class Lockout {
        private int maxAttempts = 5;
        private int durationMinutes = 30;
    }

    @Data
    public static class Mfa {
        private String issuer = "AuthServer";
    }
}
