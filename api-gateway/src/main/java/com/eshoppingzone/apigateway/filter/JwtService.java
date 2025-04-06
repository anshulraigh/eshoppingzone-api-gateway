package com.eshoppingzone.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Map;

@Service
public class JwtService {
    public static final String SECRET = "1234567812345678123456781234567812345678123456781234567812345678";

    public void validateToken(String token) {
        getAllClaims(token); // Validates the token by parsing
    }

    public Map<String, Object> extractUserDetails(String token) {
        Claims claims = getAllClaims(token);
        return Map.of(
                "userId", claims.get("userId"),
                "role", claims.get("role")
        );
    }

    private Claims getAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
