package com.pranav.authcore.service;

import com.pranav.authcore.entity.User;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

@Service
@Slf4j
public class MfaService {

    private final SecretGenerator secretGenerator;
    private final QrGenerator qrGenerator;
    private final CodeVerifier codeVerifier;

    @Value("${auth.mfa.issuer:AuthServer}")
    private String mfaIssuer;

    public MfaService() {
        this.secretGenerator = new DefaultSecretGenerator();
        this.qrGenerator = new ZxingPngQrGenerator();
        
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        this.codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
    }

    /**
     * Generates a new MFA secret for a user
     */
    public String generateMfaSecret() {
        return secretGenerator.generate();
    }

    /**
     * Generates QR code data URI for MFA setup
     */
    public String generateQrCodeDataUri(User user, String secret) {
        QrData data = new QrData.Builder()
            .label(user.getEmail())
            .secret(secret)
            .issuer(mfaIssuer)
            .build();

        try {
            return getDataUriForImage(qrGenerator.generate(data), qrGenerator.getImageMimeType());
        } catch (QrGenerationException e) {
            log.error("Failed to generate QR code for user {}", user.getId(), e);
            throw new RuntimeException("Failed to generate QR code", e);
        }
    }

    /**
     * Verifies a TOTP code against user's MFA secret
     */
    public boolean verifyMfaCode(User user, String code) {
        if (user.getMfaSecret() == null || user.getMfaSecret().isBlank()) {
            return false;
        }
        return codeVerifier.isValidCode(user.getMfaSecret(), code);
    }
}
