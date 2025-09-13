package com.spring_security.config;

import java.util.Set;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterRequest {

	private String username;
	private String email;
	private String password;
	private Set<Role> roles;
}
