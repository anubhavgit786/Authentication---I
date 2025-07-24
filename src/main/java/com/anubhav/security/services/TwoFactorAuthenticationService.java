package com.anubhav.security.services;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class TwoFactorAuthenticationService implements ITwoFactorAuthenticationService
{

    @Override
    public String generateNewSecret()
    {
        return new DefaultSecretGenerator().generate();
    }

    @Override
    public String generateQrCodeImageUri(String secret)
    {
        QrData qrData = new QrData.Builder()
                .label("Anubhav Coding 2FA Example")
                .secret(secret)
                .issuer("Anubhav-Coding")
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();
        QrGenerator qrGenerator = new ZxingPngQrGenerator();
        byte[] imageData = new byte[4];

        try
        {
            imageData = qrGenerator.generate(qrData);
        }
        catch (QrGenerationException e)
        {
            e.printStackTrace();
            log.error("Error while generating QR code", e);
        }

        return Utils.getDataUriForImage(imageData, qrGenerator.getImageMimeType());
    }

    @Override
    public boolean isOtpValid(String secret, String code)
    {
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        CodeVerifier codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        return codeVerifier.isValidCode(secret, code);
    }

    @Override
    public boolean isOtpNotValid(String secret, String code)
    {
        return !this.isOtpValid(secret, code);
    }
}
