package com.spring_security.config;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

	private final SecretKey key;
	private final long expirationMs;

	public JwtService(@Value("${app.jwt.secret}") String secret, @Value("${app.jwt.expirationMs}") long expirationMs) {
		this.key = Keys.hmacShaKeyFor(secret.getBytes());
		this.expirationMs = expirationMs;
	}

	public String generateToken(User user) {
	    Map<String, Object> claims = new HashMap<>();
	    
	    List<String> roles = user.getRoles()
	                             .stream()
	                             .map(role -> "ROLE_" + role.name())
	                             .toList();
	    
	    claims.put("roles", roles);  
	    
	    System.out.println("List of roles "+roles);

	    Date now = new Date();
	    Date exp = new Date(now.getTime() + expirationMs);
	    
	    return Jwts.builder()
	               .claims(claims)
	               .subject(user.getUsername())
	               .issuedAt(now)
	               .expiration(exp)
	               .signWith(key)
	               .compact();
	}

	public Jws<Claims> parase(String token) {
		return Jwts.parser()
				.verifyWith(key)
				.build()
				.parseSignedClaims(token);
	}

	public <T> T extractClaims(String token,
			Function<Claims, T> claimsResolver) {
		final Claims claims = parase(token).getPayload();
		return claimsResolver.apply(claims);
	}

	public String extractUsername(String token) {
		return extractClaims(token,
				Claims::getSubject);
	}

	public String extractRole(String token) {
		return extractClaims(token,
				claims -> claims.get("role",
						String.class));
	}

	public boolean isTokenValid(String token) {
		try {
			return !isExpired(token);
		} catch (JwtException e) {
			return false;
		}
	}

	private boolean isExpired(String token) {
		return extractClaims(token,
				Claims::getExpiration).before(new Date());
	}
}
