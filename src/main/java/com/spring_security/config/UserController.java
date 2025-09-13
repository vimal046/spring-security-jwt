package com.spring_security.config;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("api/auth")
@RequiredArgsConstructor
public class UserController {

	private final UserService userService;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;

	// register endpoint
	@PostMapping("/register")
	public ResponseEntity<?> register(@RequestBody RegisterRequest request) {

		User user = userService.registerUser(request.getUsername(),
				request.getEmail(),
				request.getPassword(),
				request.getRoles());
		return ResponseEntity.ok("User registered: " + user.getUsername());
	}

	// login endpoint - returns JWT in HttpOnly cookie
	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody AuthRequest request,
			HttpServletResponse response) {
		authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

		User user = userService.getByUsername(request.getUsername())
				.get();
		String token = jwtService.generateToken(user);

		// Set JWT in HttpOnly cookie
		Cookie cookie = new Cookie("JWT", token);
		cookie.setHttpOnly(true);
		cookie.setSecure(false);
		cookie.setPath("/");
		cookie.setMaxAge(24 * 60 * 60);
		response.addCookie(cookie);

		return ResponseEntity.ok("Login successful");
	}

	// logout - clear cookie
	@PostMapping("/logout")
	public ResponseEntity<?> logout(HttpServletResponse response) {

		Cookie cookie = new Cookie("JWT", null);
		cookie.setHttpOnly(true);
		cookie.setSecure(false);
		cookie.setPath("/");
		cookie.setMaxAge(0);
		response.addCookie(cookie);

		return ResponseEntity.ok("Logged out successfully");
	}

	// lock/unlock user
	@PostMapping("/lock/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<?> lockUser(@PathVariable Long id) {
		userService.lockUser(id);
		return ResponseEntity.ok("User locked");
	}

	@PostMapping("/unlock/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<?> unlockUser(@PathVariable Long id) {
		userService.unlockUser(id);
		return ResponseEntity.ok("User unlocked");
	}

	@PostMapping("/deactivate/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<?> deactivateUser(@PathVariable Long id) {
		userService.deactivateUser(id);
		return ResponseEntity.ok("user deactivated");
	}

	@PostMapping("/activate/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<?> activateUser(@PathVariable Long id) {
		userService.activateUser(id);
		return ResponseEntity.ok("User activated");
	}

}
