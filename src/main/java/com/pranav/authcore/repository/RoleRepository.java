package com.pranav.authcore.repository;

import com.pranav.authcore.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RoleRepository extends JpaRepository<Role, UUID> {
    
    Optional<Role> findByNameAndOrganization_Id(String name, UUID orgId);
    
    Optional<Role> findByNameAndOrganizationIsNull(String name);
    
    List<Role> findByOrganization_Id(UUID orgId);
    
    @Query("SELECT r FROM Role r WHERE r.organization IS NULL")
    List<Role> findSystemRoles();
    
    @Query("SELECT r FROM Role r WHERE r.organization.id = :orgId OR r.organization IS NULL")
    List<Role> findAvailableRolesForOrg(@Param("orgId") UUID orgId);
}
