package com.pranav.authcore.service;

import com.pranav.authcore.dto.AuthResponse;
import com.pranav.authcore.dto.LoginRequest;
import com.pranav.authcore.dto.RefreshTokenRequest;
import com.pranav.authcore.entity.*;
import com.pranav.authcore.exception.AccountLockedException;
import com.pranav.authcore.exception.InvalidCredentialsException;
import com.pranav.authcore.exception.InvalidTokenException;
import com.pranav.authcore.exception.TokenReuseDetectedException;
import com.pranav.authcore.repository.*;
import com.pranav.authcore.util.PasswordUtils;
import com.pranav.authcore.util.TokenUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final OrgMembershipRepository orgMembershipRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordUtils passwordUtils;
    private final TokenUtils tokenUtils;
    private final AccountLockoutService accountLockoutService;
    private final AuditService auditService;
    private final MfaService mfaService;

    @Value("${auth.refresh-token.expiry-hours:720}") // 30 days default
    private int refreshTokenExpiryHours;

    @Transactional
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmailAndDeletedAtIsNull(request.getEmail())
            .orElseThrow(() -> new InvalidCredentialsException("Invalid email or password"));

        // Check if account is locked
        accountLockoutService.checkAccountLocked(user);

        // Verify password
        if (!passwordUtils.verifyPassword(request.getPassword(), user.getPasswordHash())) {
            accountLockoutService.recordFailedLogin(user);
            auditService.logFailedLogin(user, request.getIpAddress(), request.getUserAgent());
            throw new InvalidCredentialsException("Invalid email or password");
        }

        // Check MFA if enabled
        if (user.getMfaEnabled()) {
            if (request.getMfaCode() == null || request.getMfaCode().isBlank()) {
                return AuthResponse.builder()
                    .userId(user.getId())
                    .email(user.getEmail())
                    .mfaEnabled(true)
                    .mfaRequired(true)
                    .build();
            }
            if (!mfaService.verifyMfaCode(user, request.getMfaCode())) {
                throw new InvalidCredentialsException("Invalid MFA code");
            }
        }

        // Reset failed login attempts on successful login
        accountLockoutService.resetFailedLogins(user);

        // Get org context
        Organization org = resolveOrganization(user, request.getOrgId());

        // Generate tokens
        String refreshToken = tokenUtils.generateSecureToken();
        String tokenHash = tokenUtils.hashToken(refreshToken);

        RefreshToken refreshTokenEntity = RefreshToken.builder()
            .user(user)
            .organization(org)
            .tokenHash(tokenHash)
            .familyId(UUID.randomUUID())
            .expiresAt(Instant.now().plus(Duration.ofHours(refreshTokenExpiryHours)))
            .ipAddress(request.getIpAddress())
            .userAgent(request.getUserAgent())
            .build();

        refreshTokenRepository.save(refreshTokenEntity);

        // Update last login
        user.setLastLoginAt(Instant.now());
        userRepository.save(user);

        // Audit log
        auditService.logSuccessfulLogin(user, org, request.getIpAddress(), request.getUserAgent());

        return AuthResponse.builder()
            .userId(user.getId())
            .email(user.getEmail())
            .orgId(org != null ? org.getId() : null)
            .orgSlug(org != null ? org.getSlug() : null)
            .refreshToken(refreshToken)
            .refreshTokenExpiresAt(refreshTokenEntity.getExpiresAt())
            .mfaEnabled(user.getMfaEnabled())
            .mfaRequired(false)
            .build();
    }

    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request) {
        String tokenHash = tokenUtils.hashToken(request.getRefreshToken());

        RefreshToken currentToken = refreshTokenRepository.findByTokenHash(tokenHash)
            .orElseThrow(() -> new InvalidTokenException("Invalid or expired refresh token"));

        // Check if token is expired
        if (currentToken.getExpiresAt().isBefore(Instant.now())) {
            throw new InvalidTokenException("Refresh token has expired");
        }

        // CRITICAL: Check if token was already revoked (reuse detection)
        if (currentToken.getRevokedAt() != null) {
            log.warn("Token reuse detected! Family: {}, User: {}", 
                currentToken.getFamilyId(), currentToken.getUser().getId());
            
            // Revoke all tokens in this family
            refreshTokenRepository.revokeAllTokensInFamily(
                currentToken.getFamilyId(),
                Instant.now(),
                RefreshToken.RevokedReason.REUSE_DETECTED
            );
            
            auditService.logTokenReuseDetected(
                currentToken.getUser(),
                currentToken.getOrganization(),
                request.getIpAddress()
            );
            
            throw new TokenReuseDetectedException("Token reuse detected - all tokens revoked");
        }

        // Rotate the token
        String newRefreshToken = tokenUtils.generateSecureToken();
        String newTokenHash = tokenUtils.hashToken(newRefreshToken);

        RefreshToken newToken = RefreshToken.builder()
            .user(currentToken.getUser())
            .organization(currentToken.getOrganization())
            .tokenHash(newTokenHash)
            .familyId(currentToken.getFamilyId()) // same family
            .expiresAt(Instant.now().plus(Duration.ofHours(refreshTokenExpiryHours)))
            .ipAddress(request.getIpAddress())
            .userAgent(request.getUserAgent())
            .build();

        refreshTokenRepository.save(newToken);

        // Revoke old token
        currentToken.setRevokedAt(Instant.now());
        currentToken.setRevokedReason(RefreshToken.RevokedReason.ROTATED);
        currentToken.setReplacedByToken(newToken);
        refreshTokenRepository.save(currentToken);

        auditService.logTokenRefresh(currentToken.getUser(), currentToken.getOrganization());

        return AuthResponse.builder()
            .userId(currentToken.getUser().getId())
            .email(currentToken.getUser().getEmail())
            .orgId(currentToken.getOrganization() != null ? currentToken.getOrganization().getId() : null)
            .orgSlug(currentToken.getOrganization() != null ? currentToken.getOrganization().getSlug() : null)
            .refreshToken(newRefreshToken)
            .refreshTokenExpiresAt(newToken.getExpiresAt())
            .build();
    }

    @Transactional
    public void logout(String refreshToken) {
        String tokenHash = tokenUtils.hashToken(refreshToken);
        
        RefreshToken token = refreshTokenRepository.findByTokenHash(tokenHash)
            .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

        token.setRevokedAt(Instant.now());
        token.setRevokedReason(RefreshToken.RevokedReason.LOGOUT);
        refreshTokenRepository.save(token);

        auditService.logLogout(token.getUser(), token.getOrganization());
    }

    @Transactional
    public void revokeAllUserTokens(UUID userId) {
        refreshTokenRepository.revokeAllUserTokens(
            userId,
            Instant.now(),
            RefreshToken.RevokedReason.ADMIN_REVOKED
        );
    }

    private Organization resolveOrganization(User user, UUID requestedOrgId) {
        if (requestedOrgId == null) {
            // Return first active org membership
            return orgMembershipRepository.findActiveByUserId(user.getId())
                .stream()
                .findFirst()
                .map(OrgMembership::getOrganization)
                .orElse(null);
        }

        // Verify user has access to requested org
        OrgMembership membership = orgMembershipRepository
            .findByOrganization_IdAndUser_Id(requestedOrgId, user.getId())
            .orElseThrow(() -> new InvalidCredentialsException("User does not have access to this organization"));

        return membership.getOrganization();
    }
}
