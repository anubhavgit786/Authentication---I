package com.anubhav.security.services;

public interface ITwoFactorAuthenticationService
{
    String generateNewSecret();
    String generateQrCodeImageUri(String secret);
    boolean isOtpValid(String secret, String code);
    boolean isOtpNotValid(String secret, String code);
}
