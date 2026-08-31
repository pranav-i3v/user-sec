package com.pranav.authcore.repository;

import com.pranav.authcore.entity.AuthAuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public interface AuthAuditLogRepository extends JpaRepository<AuthAuditLog, UUID> {
    
    List<AuthAuditLog> findByUser_IdOrderByCreatedAtDesc(UUID userId);
    
    Page<AuthAuditLog> findByUser_IdOrderByCreatedAtDesc(UUID userId, Pageable pageable);
    
    List<AuthAuditLog> findByOrganization_IdOrderByCreatedAtDesc(UUID orgId);
    
    @Query("SELECT aal FROM AuthAuditLog aal " +
           "WHERE aal.eventType = :eventType " +
           "AND aal.createdAt >= :since")
    List<AuthAuditLog> findByEventTypeAndCreatedAtAfter(@Param("eventType") String eventType,
                                                          @Param("since") Instant since);
}
