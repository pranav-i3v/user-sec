package com.pranav.authcore.service;

import com.pranav.authcore.dto.UserPermissionsDTO;
import com.pranav.authcore.entity.Permission;
import com.pranav.authcore.entity.RolePermission;
import com.pranav.authcore.repository.RolePermissionRepository;
import com.pranav.authcore.repository.UserRoleRepository;
import com.pranav.authcore.util.PathMatcher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class RbacService {

    private final UserRoleRepository userRoleRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final PathMatcher pathMatcher;

    /**
     * Retrieves all permissions for a user within an organization
     */
    @Transactional(readOnly = true)
    public UserPermissionsDTO getUserPermissions(UUID userId, UUID orgId) {
        // Get all role IDs for this user in this org
        List<UUID> roleIds = userRoleRepository.findRoleIdsByUserIdAndOrgId(userId, orgId);

        if (roleIds.isEmpty()) {
            return UserPermissionsDTO.builder()
                .userId(userId)
                .orgId(orgId)
                .roles(List.of())
                .permissions(List.of())
                .build();
        }

        // Get all permissions for these roles
        List<RolePermission> rolePermissions = rolePermissionRepository.findByRoleIdIn(roleIds);

        List<UserPermissionsDTO.PermissionDTO> permissions = rolePermissions.stream()
            .map(rp -> {
                Permission p = rp.getPermission();
                return UserPermissionsDTO.PermissionDTO.builder()
                    .code(p.getCode())
                    .pathPattern(p.getPathPattern())
                    .httpMethod(p.getHttpMethod().name())
                    .build();
            })
            .distinct()
            .collect(Collectors.toList());

        return UserPermissionsDTO.builder()
            .userId(userId)
            .orgId(orgId)
            .permissions(permissions)
            .build();
    }

    /**
     * Checks if a user has permission to access a specific path with HTTP method
     */
    @Transactional(readOnly = true)
    public boolean hasPermission(UUID userId, UUID orgId, String requestPath, String httpMethod) {
        UserPermissionsDTO userPermissions = getUserPermissions(userId, orgId);

        for (UserPermissionsDTO.PermissionDTO permission : userPermissions.getPermissions()) {
            boolean pathMatches = pathMatcher.matches(permission.getPathPattern(), requestPath);
            boolean methodMatches = pathMatcher.matchesMethod(permission.getHttpMethod(), httpMethod);

            if (pathMatches && methodMatches) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks if a user has a specific role within an organization
     */
    @Transactional(readOnly = true)
    public boolean hasRole(UUID userId, UUID orgId, String roleName) {
        return userRoleRepository.findByUserIdAndOrgId(userId, orgId)
            .stream()
            .anyMatch(ur -> ur.getRole().getName().equalsIgnoreCase(roleName));
    }
}
