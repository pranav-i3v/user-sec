package com.pranav.authcore.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.util.UUID;

@Data
public class LoginRequest {
    
    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;
    
    @NotBlank(message = "Password is required")
    private String password;
    
    private UUID orgId; // optional: login to specific org context
    
    private String mfaCode; // optional: TOTP code if MFA enabled
    
    private String ipAddress;
    
    private String userAgent;
}
