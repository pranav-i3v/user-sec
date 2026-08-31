package com.pranav.authcore.repository;

import com.pranav.authcore.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    
    Optional<RefreshToken> findByTokenHash(String tokenHash);
    
    @Query("SELECT rt FROM RefreshToken rt " +
           "WHERE rt.user.id = :userId " +
           "AND rt.revokedAt IS NULL " +
           "AND rt.expiresAt > :now")
    List<RefreshToken> findActiveTokensByUserId(@Param("userId") UUID userId, 
                                                  @Param("now") Instant now);
    
    @Query("SELECT rt FROM RefreshToken rt " +
           "WHERE rt.familyId = :familyId " +
           "ORDER BY rt.issuedAt DESC")
    List<RefreshToken> findByFamilyIdOrderByIssuedAtDesc(@Param("familyId") UUID familyId);
    
    @Modifying
    @Query("UPDATE RefreshToken rt " +
           "SET rt.revokedAt = :revokedAt, rt.revokedReason = :reason " +
           "WHERE rt.familyId = :familyId AND rt.revokedAt IS NULL")
    void revokeAllTokensInFamily(@Param("familyId") UUID familyId, 
                                   @Param("revokedAt") Instant revokedAt,
                                   @Param("reason") RefreshToken.RevokedReason reason);
    
    @Modifying
    @Query("UPDATE RefreshToken rt " +
           "SET rt.revokedAt = :revokedAt, rt.revokedReason = :reason " +
           "WHERE rt.user.id = :userId AND rt.revokedAt IS NULL")
    void revokeAllUserTokens(@Param("userId") UUID userId, 
                              @Param("revokedAt") Instant revokedAt,
                              @Param("reason") RefreshToken.RevokedReason reason);
}
