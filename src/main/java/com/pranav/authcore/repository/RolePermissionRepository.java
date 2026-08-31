package com.pranav.authcore.repository;

import com.pranav.authcore.entity.RolePermission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface RolePermissionRepository extends JpaRepository<RolePermission, RolePermission.RolePermissionId> {
    
    @Query("SELECT rp FROM RolePermission rp WHERE rp.role.id = :roleId")
    List<RolePermission> findByRoleId(@Param("roleId") UUID roleId);
    
    @Query("SELECT rp FROM RolePermission rp WHERE rp.role.id IN :roleIds")
    List<RolePermission> findByRoleIdIn(@Param("roleIds") List<UUID> roleIds);
    
    void deleteByRole_Id(UUID roleId);
}
