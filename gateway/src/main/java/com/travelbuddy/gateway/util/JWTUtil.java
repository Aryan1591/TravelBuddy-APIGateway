package com.travelbuddy.gateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.function.Function;

@Component
public class JWTUtil {
    @Value("${security.secretToken}")
    private String SECRET_TOKEN;

    private Key getSignature() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_TOKEN);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public Jws<Claims> validateJWTToken(String token) {
        return Jwts.parserBuilder().setSigningKey(getSignature()).build().parseClaimsJws(token);
    }

    public String extractUserName(String jwtToken) {
        return extractClaim(jwtToken, Claims::getSubject);
    }

    public <T> T extractClaim(String jwtToken, Function<Claims, T>claimsResolver) {
        return claimsResolver.apply(extractAllClaims(jwtToken));
    }

    private Claims extractAllClaims(String jwtToken) {
        return Jwts.parserBuilder().setSigningKey(getSignature())
                .build().parseClaimsJws(jwtToken).getBody();
    }
}
