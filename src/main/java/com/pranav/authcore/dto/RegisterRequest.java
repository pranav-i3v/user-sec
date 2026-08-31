package com.pranav.authcore.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {
    private String email;
    private String password;
    private UUID orgId; // optional - can be null for user-only registration
    private String ipAddress;
    private String userAgent;
}
