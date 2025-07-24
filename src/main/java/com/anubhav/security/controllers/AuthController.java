package com.anubhav.security.controllers;

import com.anubhav.security.dtos.AuthenticationRequest;
import com.anubhav.security.dtos.AuthenticationResponse;
import com.anubhav.security.dtos.RegisterRequest;
import com.anubhav.security.dtos.VerificationRequest;
import com.anubhav.security.services.IAuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController
{
    @Autowired
    private IAuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest registerRequest)
    {
        AuthenticationResponse response = authenticationService.register(registerRequest);
        if(registerRequest.isMfaEnabled())
        {
            return ResponseEntity.ok(response);
        }

        return ResponseEntity.accepted().build();
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest authenticationRequest)
    {
        AuthenticationResponse response = authenticationService.authenticate(authenticationRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh-token")
    public void refreshToken(HttpServletRequest req, HttpServletResponse res) throws IOException
    {
        authenticationService.refreshToken(req, res);
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyCode(@RequestBody VerificationRequest verificationRequest) throws IOException
    {
        AuthenticationResponse response = authenticationService.verifyCode(verificationRequest);
        return ResponseEntity.ok(response);
    }
}
