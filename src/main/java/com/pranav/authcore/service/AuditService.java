package com.pranav.authcore.service;

import com.pranav.authcore.entity.AuthAuditLog;
import com.pranav.authcore.entity.Organization;
import com.pranav.authcore.entity.User;
import com.pranav.authcore.repository.AuthAuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditService {

    private final AuthAuditLogRepository auditLogRepository;

    @Transactional
    public void logSuccessfulLogin(User user, Organization org, String ipAddress, String userAgent) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", user.getId().toString());
        metadata.put("email", user.getEmail());
        if (org != null) {
            metadata.put("orgId", org.getId().toString());
            metadata.put("orgSlug", org.getSlug());
        }

        AuthAuditLog auditLog = AuthAuditLog.builder()
            .user(user)
            .organization(org)
            .eventType("LOGIN_SUCCESS")
            .metadata(metadata)
            .ipAddress(ipAddress)
            .userAgent(userAgent)
            .build();

        auditLogRepository.save(auditLog);
    }

    @Transactional
    public void logFailedLogin(User user, String ipAddress, String userAgent) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", user.getId().toString());
        metadata.put("email", user.getEmail());
        metadata.put("failedAttempts", user.getFailedLoginAttempts() + 1);

        AuthAuditLog auditLog = AuthAuditLog.builder()
            .user(user)
            .eventType("LOGIN_FAILED")
            .metadata(metadata)
            .ipAddress(ipAddress)
            .userAgent(userAgent)
            .build();

        auditLogRepository.save(auditLog);
    }

    @Transactional
    public void logTokenRefresh(User user, Organization org) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", user.getId().toString());
        if (org != null) {
            metadata.put("orgId", org.getId().toString());
        }

        AuthAuditLog auditLog = AuthAuditLog.builder()
            .user(user)
            .organization(org)
            .eventType("TOKEN_REFRESHED")
            .metadata(metadata)
            .build();

        auditLogRepository.save(auditLog);
    }

    @Transactional
    public void logTokenReuseDetected(User user, Organization org, String ipAddress) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", user.getId().toString());
        metadata.put("severity", "HIGH");
        if (org != null) {
            metadata.put("orgId", org.getId().toString());
        }

        AuthAuditLog auditLog = AuthAuditLog.builder()
            .user(user)
            .organization(org)
            .eventType("TOKEN_REUSE_DETECTED")
            .metadata(metadata)
            .ipAddress(ipAddress)
            .build();

        auditLogRepository.save(auditLog);
        log.warn("Token reuse detected for user: {}, org: {}, IP: {}", 
            user.getId(), org != null ? org.getId() : "null", ipAddress);
    }

    @Transactional
    public void logLogout(User user, Organization org) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", user.getId().toString());
        if (org != null) {
            metadata.put("orgId", org.getId().toString());
        }

        AuthAuditLog auditLog = AuthAuditLog.builder()
            .user(user)
            .organization(org)
            .eventType("LOGOUT")
            .metadata(metadata)
            .build();

        auditLogRepository.save(auditLog);
    }

    @Transactional
    public void logRoleGranted(User user, Organization org, String roleName, User grantedBy) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", user.getId().toString());
        metadata.put("roleName", roleName);
        metadata.put("grantedBy", grantedBy.getId().toString());

        AuthAuditLog auditLog = AuthAuditLog.builder()
            .user(user)
            .organization(org)
            .eventType("ROLE_GRANTED")
            .metadata(metadata)
            .build();

        auditLogRepository.save(auditLog);
    }

    @Transactional
    public void logRoleRevoked(User user, Organization org, String roleName, User revokedBy) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("userId", user.getId().toString());
        metadata.put("roleName", roleName);
        metadata.put("revokedBy", revokedBy.getId().toString());

        AuthAuditLog auditLog = AuthAuditLog.builder()
            .user(user)
            .organization(org)
            .eventType("ROLE_REVOKED")
            .metadata(metadata)
            .build();

        auditLogRepository.save(auditLog);
    }
}
