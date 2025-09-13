package com.spring_security.config;

import java.time.LocalDate;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@SuppressWarnings("serial")
@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {

	private final User user;

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return user.getRoles()
				.stream()
				.map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
				.toList();
	}

	@Override
	public String getUsername() {
		return user.getUsername();
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}

	public boolean isAccountNonExpired() {
		return user.getAccountExpiryDate() == null || user.getAccountExpiryDate()
				.isAfter(LocalDate.now());
	}

	public boolean isAccountNonLocked() {
		return !user.isLocked();
	}

	public boolean isCredentialsNonExpired() {
		return user.getCredentialsExpiryDate() == null || user.getCredentialsExpiryDate()
				.isAfter(LocalDate.now());
	}

	public boolean isEnabled() {
		return user.isActive();
	}
}
