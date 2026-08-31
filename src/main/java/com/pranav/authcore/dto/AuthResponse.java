package com.pranav.authcore.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    
    private UUID userId;
    private String email;
    private UUID orgId;
    private String orgSlug;
    
    private String accessToken; // to be implemented (could be opaque token or session ID)
    private String refreshToken; // plaintext token (sent once)
    
    private Instant accessTokenExpiresAt;
    private Instant refreshTokenExpiresAt;
    
    private boolean mfaEnabled;
    private boolean mfaRequired; // true if MFA needed but not provided
}
