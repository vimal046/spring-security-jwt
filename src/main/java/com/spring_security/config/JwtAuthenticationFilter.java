package com.spring_security.config;

import java.io.IOException;
import java.util.List;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final JwtService jwtService;
	private final CustomUserDetailService cutCustomUserDetailService;

	@SuppressWarnings("null")
	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response,
			FilterChain filterChain) throws ServletException, IOException {

		String token = null;

		if (request.getCookies() != null) {
			for (Cookie cookie : request.getCookies()) {
				if ("JWT".equals(cookie.getName())) {
					token = cookie.getValue();
					break;
				}
			}
		}

		if (token == null) {
			final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
			if (authHeader != null && authHeader.startsWith("Bearer ")) {
				token = authHeader.substring(7);
			}
		}

		if (token == null) {
			filterChain.doFilter(request,
					response);
			return;
		}

		String username = jwtService.extractUsername(token);
		
		System.out.println("JWT Token: " + token);
		System.out.println("Username from JWT: " + username);

		if (username != null && SecurityContextHolder.getContext()
				.getAuthentication() == null) {

			if (jwtService.isTokenValid(token)) {
				
				System.out.println("Setting authentication for user: " + username);
				
				UserDetails userDetails = cutCustomUserDetailService.loadUserByUsername(username);
				UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userDetails, null,
						userDetails.getAuthorities());
				auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext()
						.setAuthentication(auth);
			}
		}
		filterChain.doFilter(request,
				response);
	}

}
