package com.pranav.authcore.repository;

import com.pranav.authcore.entity.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, UUID> {
    
    List<UserRole> findByOrgMembership_Id(UUID membershipId);
    
    @Query("SELECT ur FROM UserRole ur " +
           "WHERE ur.orgMembership.user.id = :userId " +
           "AND ur.orgMembership.organization.id = :orgId")
    List<UserRole> findByUserIdAndOrgId(@Param("userId") UUID userId, 
                                         @Param("orgId") UUID orgId);
    
    @Query("SELECT DISTINCT ur.role.id FROM UserRole ur " +
           "WHERE ur.orgMembership.user.id = :userId " +
           "AND ur.orgMembership.organization.id = :orgId")
    List<UUID> findRoleIdsByUserIdAndOrgId(@Param("userId") UUID userId, 
                                            @Param("orgId") UUID orgId);
    
    void deleteByOrgMembership_Id(UUID membershipId);
}
