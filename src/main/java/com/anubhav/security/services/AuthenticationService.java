package com.anubhav.security.services;

import com.anubhav.security.dtos.AuthenticationRequest;
import com.anubhav.security.dtos.AuthenticationResponse;
import com.anubhav.security.dtos.RegisterRequest;
import com.anubhav.security.dtos.VerificationRequest;
import com.anubhav.security.models.Role;
import com.anubhav.security.models.Token;
import com.anubhav.security.models.TokenType;
import com.anubhav.security.models.User;
import com.anubhav.security.repositories.TokenRepository;
import com.anubhav.security.repositories.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class AuthenticationService implements IAuthenticationService
{
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenRepository tokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private IJwtService jwtService;

    @Autowired
    private ITwoFactorAuthenticationService twoFactorAuthenticationService;

    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest)
    {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getEmail(), authenticationRequest.getPassword()));
        var user = userRepository.findByEmail(authenticationRequest.getEmail()).orElseThrow();
        if(user.isMfaEnabled())
        {
            return AuthenticationResponse.builder()
                    .accessToken("")
                    .refreshToken("")
                    .mfaEnabled(true)
                    .build();
        }
        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, accessToken);
        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .mfaEnabled(false)
                .build();
    }

    @Override
    public AuthenticationResponse register(RegisterRequest registerRequest)
    {
        var user = User.builder()
                .firstname(registerRequest.getFirstname())
                .lastname(registerRequest.getLastname())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(registerRequest.getRole())
                .mfaEnabled(registerRequest.isMfaEnabled())
                .build();

        if(registerRequest.isMfaEnabled())
        {
            user.setSecret(twoFactorAuthenticationService.generateNewSecret());
        }

        var savedUser = userRepository.save(user);

        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(savedUser, accessToken);

        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .mfaEnabled(user.isMfaEnabled())
                .secretImageUri(twoFactorAuthenticationService.generateQrCodeImageUri(user.getSecret()))
                .build();
    }

    public void refreshToken(HttpServletRequest req, HttpServletResponse res) throws IOException
    {
        final String authHeader = req.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;

        if (authHeader == null || !authHeader.startsWith("Bearer "))
        {
            return;
        }

        refreshToken = authHeader.substring(7);

        userEmail = jwtService.extractUsername(refreshToken);
        if(userEmail != null)
        {
            var userDetails = userRepository.findByEmail(userEmail).orElseThrow();
            boolean accessTokenCheck = false;
            if(jwtService.isTokenValid(refreshToken, userDetails, accessTokenCheck))
            {
                var accessToken = jwtService.generateToken(userDetails);
                revokeAllUserTokens(userDetails);
                saveUserToken(userDetails, accessToken);
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .mfaEnabled(false)
                        .build();

                new ObjectMapper().writeValue(res.getOutputStream(), authResponse);
            }
        }
    }

    @Override
    public AuthenticationResponse verifyCode(VerificationRequest verificationRequest)
    {
        var user = userRepository.findByEmail(verificationRequest.getEmail()).orElseThrow();

        if(twoFactorAuthenticationService.isOtpNotValid(user.getSecret(), verificationRequest.getCode()))
        {
            throw new BadCredentialsException("Code is not valid");
        }

        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);
        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .mfaEnabled(user.isMfaEnabled())
                .build();
    }

    private void saveUserToken(User user, String jwtToken)
    {
        var token = Token.builder()
                .token(jwtToken)
                .user(user)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user)
    {
        var validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }
}
