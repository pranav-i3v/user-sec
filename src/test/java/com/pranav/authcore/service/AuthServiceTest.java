package com.pranav.authcore.service;

import com.pranav.authcore.dto.AuthResponse;
import com.pranav.authcore.dto.LoginRequest;
import com.pranav.authcore.entity.User;
import com.pranav.authcore.exception.InvalidCredentialsException;
import com.pranav.authcore.repository.OrgMembershipRepository;
import com.pranav.authcore.repository.RefreshTokenRepository;
import com.pranav.authcore.repository.UserRepository;
import com.pranav.authcore.util.PasswordUtils;
import com.pranav.authcore.util.TokenUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private OrgMembershipRepository orgMembershipRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private PasswordUtils passwordUtils;

    @Mock
    private TokenUtils tokenUtils;

    @Mock
    private AccountLockoutService accountLockoutService;

    @Mock
    private AuditService auditService;

    @Mock
    private MfaService mfaService;

    @InjectMocks
    private AuthService authService;

    private User testUser;
    private LoginRequest loginRequest;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
            .id(UUID.randomUUID())
            .email("test@example.com")
            .passwordHash("$2a$12$hashedPassword")
            .status(User.UserStatus.ACTIVE)
            .mfaEnabled(false)
            .failedLoginAttempts((short) 0)
            .build();

        loginRequest = new LoginRequest();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("password123");
        loginRequest.setIpAddress("192.168.1.1");
        loginRequest.setUserAgent("Mozilla/5.0");
    }

    @Test
    void login_Success_WithoutMFA() {
        // Arrange
        when(userRepository.findByEmailAndDeletedAtIsNull(loginRequest.getEmail()))
            .thenReturn(Optional.of(testUser));
        when(passwordUtils.verifyPassword(loginRequest.getPassword(), testUser.getPasswordHash()))
            .thenReturn(true);
        when(tokenUtils.generateSecureToken())
            .thenReturn("secure-token-123");
        when(tokenUtils.hashToken("secure-token-123"))
            .thenReturn("hashed-token-123");
        when(orgMembershipRepository.findActiveByUserId(testUser.getId()))
            .thenReturn(java.util.Collections.emptyList());

        // Act
        AuthResponse response = authService.login(loginRequest);

        // Assert
        assertNotNull(response);
        assertEquals(testUser.getId(), response.getUserId());
        assertEquals(testUser.getEmail(), response.getEmail());
        assertEquals("secure-token-123", response.getRefreshToken());
        assertFalse(response.isMfaRequired());

        verify(accountLockoutService).checkAccountLocked(testUser);
        verify(accountLockoutService).resetFailedLogins(testUser);
        verify(auditService).logSuccessfulLogin(eq(testUser), any(), eq(loginRequest.getIpAddress()), eq(loginRequest.getUserAgent()));
        verify(refreshTokenRepository).save(any());
        verify(userRepository).save(testUser);
    }

    @Test
    void login_Failure_InvalidPassword() {
        // Arrange
        when(userRepository.findByEmailAndDeletedAtIsNull(loginRequest.getEmail()))
            .thenReturn(Optional.of(testUser));
        when(passwordUtils.verifyPassword(loginRequest.getPassword(), testUser.getPasswordHash()))
            .thenReturn(false);

        // Act & Assert
        assertThrows(InvalidCredentialsException.class, () -> authService.login(loginRequest));

        verify(accountLockoutService).recordFailedLogin(testUser);
        verify(auditService).logFailedLogin(testUser, loginRequest.getIpAddress(), loginRequest.getUserAgent());
        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void login_Failure_UserNotFound() {
        // Arrange
        when(userRepository.findByEmailAndDeletedAtIsNull(loginRequest.getEmail()))
            .thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(InvalidCredentialsException.class, () -> authService.login(loginRequest));

        verify(passwordUtils, never()).verifyPassword(any(), any());
        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void login_MfaRequired_WhenEnabled() {
        // Arrange
        testUser.setMfaEnabled(true);
        loginRequest.setMfaCode(null); // No MFA code provided

        when(userRepository.findByEmailAndDeletedAtIsNull(loginRequest.getEmail()))
            .thenReturn(Optional.of(testUser));
        when(passwordUtils.verifyPassword(loginRequest.getPassword(), testUser.getPasswordHash()))
            .thenReturn(true);

        // Act
        AuthResponse response = authService.login(loginRequest);

        // Assert
        assertNotNull(response);
        assertTrue(response.isMfaRequired());
        assertNull(response.getRefreshToken()); // No token issued yet
        verify(refreshTokenRepository, never()).save(any());
    }
}
