package com.anubhav.security.services;


import io.jsonwebtoken.Claims;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Map;
import java.util.function.Function;

public interface IJwtService
{
    String extractUsername(String jwtToken);
    <T> T extractClaim(String jwtToken, Function<Claims, T> claimsResolver);
    String generateToken(UserDetails userDetails);
    String generateRefreshToken(UserDetails userDetails);
    String generateToken(Map<String, Object> extraClaims, UserDetails userDetails);
    boolean isTokenValid(String jwt, UserDetails userDetails, boolean accessTokenCheck);
}
