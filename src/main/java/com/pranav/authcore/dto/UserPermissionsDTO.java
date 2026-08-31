package com.pranav.authcore.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserPermissionsDTO {
    
    private UUID userId;
    private UUID orgId;
    private List<String> roles;
    private List<PermissionDTO> permissions;
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PermissionDTO {
        private String code;
        private String pathPattern;
        private String httpMethod;
    }
}
