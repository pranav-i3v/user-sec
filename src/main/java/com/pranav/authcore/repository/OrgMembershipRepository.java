package com.pranav.authcore.repository;

import com.pranav.authcore.entity.OrgMembership;
import com.pranav.authcore.entity.Organization;
import com.pranav.authcore.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface OrgMembershipRepository extends JpaRepository<OrgMembership, UUID> {
    
    Optional<OrgMembership> findByOrganizationAndUser(Organization organization, User user);
    
    Optional<OrgMembership> findByOrganization_IdAndUser_Id(UUID orgId, UUID userId);
    
    List<OrgMembership> findByUser_Id(UUID userId);
    
    List<OrgMembership> findByOrganization_Id(UUID orgId);
    
    @Query("SELECT om FROM OrgMembership om WHERE om.user.id = :userId AND om.status = 'ACTIVE'")
    List<OrgMembership> findActiveByUserId(@Param("userId") UUID userId);
}
