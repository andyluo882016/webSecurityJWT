package com.example.demo.util;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtJutil implements Serializable{

	private static final long serialVersionUID = -2550185165626007488L;
    private String SECURET_KEY="securet";

	@Value("${jwt.secret}")
	private String secret;
	 
	 public String extractUsername(String token) {
		 return extractClaim(token, Claims::getSubject);
	 }

	public Date extraIssuedAtDateFromToken(String token) {
		return extractClaim(token, Claims::getIssuedAt);
	}
	 public Date extractExpiration(String token) {
		 return extractClaim(token, Claims::getExpiration);
	 }
	 
	 private Claims extractAllClaims(String token) {
		 //return Jwts.parser().setSigningKey(SECURET_KEY).parseClaimsJws(token).getBody();
		 return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
	 }
	 
	 public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		 final Claims claims = extractAllClaims(token);
		 return claimsResolver.apply(claims);
	 }

	 private Boolean isTokenExpired(String token) {
		 return extractExpiration(token).before(new Date());
	 }
	 
	 public String generateToken(UserDetails userDetails) {
		 Map<String, Object> claims =new HashMap<>();
		 return createToken(claims, userDetails.getUsername());
	 }
	 
	 public String createToken(Map<String, Object> claims, String subject) {
		 return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				 .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
				 .signWith(SignatureAlgorithm.HS256, secret).compact();
	 }
	 //HS256
	 
	 public Boolean validateToken(String token, UserDetails userDetails) {
		 final String username= extractUsername(token);
		 return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	 }
}
