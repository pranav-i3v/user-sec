package com.pranav.authcore.repository;

import com.pranav.authcore.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, UUID> {
    
    Optional<Permission> findByCode(String code);
    
    Optional<Permission> findByPathPatternAndHttpMethod(String pathPattern, Permission.HttpMethod httpMethod);
    
    boolean existsByCode(String code);
}
