package com.anubhav.security.services;

import com.anubhav.security.dtos.AuthenticationRequest;
import com.anubhav.security.dtos.AuthenticationResponse;
import com.anubhav.security.dtos.RegisterRequest;
import com.anubhav.security.dtos.VerificationRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public interface IAuthenticationService
{
    AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest);
    AuthenticationResponse register(RegisterRequest registerRequest);
    void refreshToken(HttpServletRequest req, HttpServletResponse res) throws IOException;
    AuthenticationResponse verifyCode(VerificationRequest verificationRequest);
}
