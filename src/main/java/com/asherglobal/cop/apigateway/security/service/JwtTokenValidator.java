package com.asherglobal.cop.apigateway.security.service;

import com.asherglobal.cop.apigateway.security.authentication.JwtAuthentication;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

@Service
public class JwtTokenValidator {

    @Value("${jwt.secret.key}")
    private String secretKey;

    private SecretKey signingKey;

    @PostConstruct
    public void init() {
        byte[] keyBytes = Base64.getDecoder().decode(secretKey);
        signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public JwtAuthentication validate(String token) {

        Claims claims = extractAllClaims(token);

        String userId = claims.getSubject();

        if (userId == null || userId.isBlank()) {
            throw new JwtException("JWT subject is missing");
        }

        String tokenType = claims.get("type", String.class);

        if (!"ACCESS".equals(tokenType)) {
            throw new JwtException("Invalid token type");
        }

        List<String> roles = extractRoles(claims);

        List<GrantedAuthority> authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .map(GrantedAuthority.class::cast)
                .toList();

        return new JwtAuthentication(
                userId,
                authorities
        );
    }

    public Claims extractAllClaims(String token) {

        if (token == null || token.isBlank()) {
            throw new JwtException("JWT token is missing");
        }

        Jws<Claims> parsedToken = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token);

        return parsedToken.getPayload();
    }

    private List<String> extractRoles(Claims claims) {

        Object rolesClaim = claims.get("roles");

        if (rolesClaim == null) {
            return Collections.emptyList();
        }

        if (!(rolesClaim instanceof Collection<?> roles)) {
            throw new JwtException("Invalid roles claim");
        }

        return roles.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .toList();
    }

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    public String extractTokenType(String token) {
        return extractAllClaims(token).get("type", String.class);
    }

    public String extractTenantId(String token) {
        return extractAllClaims(token).get("tenant_id", String.class);
    }
}