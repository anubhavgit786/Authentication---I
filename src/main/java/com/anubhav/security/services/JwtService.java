package com.anubhav.security.services;

import com.anubhav.security.repositories.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


@Service
public class JwtService implements IJwtService
{
    @Value("${application.security.jwt.secret-key}")
    private String JWT_SECRET_KEY;

    @Value("${application.security.jwt.expiration}")
    private Long jwtExpirationMs;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private Long refreshTokenExpirationMs;

    @Autowired
    private TokenRepository tokenRepository;

    @Override
    public String extractUsername(String jwtToken)
    {
        //Function<Claims, String> claimsResolver = claims -> claims.getSubject();
        //Function<Claims, String> claimsResolver = claims -> claims.get("sub");
        return extractClaim(jwtToken, Claims::getSubject);
    }

    public String generateToken(UserDetails userDetails)
    {
        return generateToken(new HashMap<>(), userDetails);
    }

    public boolean isTokenValid(String jwtToken, UserDetails userDetails, boolean accessTokenCheck)
    {
        final String username = extractUsername(jwtToken);
        if(accessTokenCheck)
        {
            var isTokenValid = tokenRepository.findByToken(jwtToken).map(token -> !token.isExpired() && !token.isRevoked()).orElse(false);
            return (username.equals(userDetails.getUsername())) && !isTokenExpired(jwtToken) && isTokenValid;
        }

        return (username.equals(userDetails.getUsername())) && !isTokenExpired(jwtToken);
    }

    private boolean isTokenExpired(String jwtToken)
    {
        return extractExpiration(jwtToken).before(new Date());
    }

    private Date extractExpiration(String jwtToken)
    {
        return extractClaim(jwtToken, Claims::getExpiration);
    }

    public String generateRefreshToken(UserDetails userDetails)
    {
        return buildToken(new HashMap<>(), userDetails, refreshTokenExpirationMs);
    }

    public String generateToken( Map<String, Object> extraClaims, UserDetails userDetails)
    {
        return buildToken(extraClaims, userDetails, jwtExpirationMs);
    }

    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, Long expiration)
    {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public <T> T extractClaim(String jwtToken, Function<Claims, T> claimsResolver)
    {
        final Claims claims = extractAllClaims(jwtToken);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String jwtToken)
    {
        return Jwts
                .parser()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();

       /* {
                "sub": "anubhav123",
                "role": "admin",
                "exp": 1725000000,
                "iat": 1724900000
        }*/
    }

    private Key getSignInKey()
    {
        byte[] keyBytes = Decoders.BASE64.decode(JWT_SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
