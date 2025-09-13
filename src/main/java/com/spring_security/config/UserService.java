package com.spring_security.config;

import java.time.LocalDate;
import java.util.Optional;
import java.util.Set;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	// Register user
	public User registerUser(String username,
			String email,
			String password,
			Set<Role> roles) {
		User user = User.builder()
				.username(username)
				.email(email)
				.password(passwordEncoder.encode(password))
				.roles(roles)
				.active(true)
				.locked(false)
				.accountExpiryDate(LocalDate.now()
						.plusMonths(1))
				.credentialsExpiryDate(LocalDate.now()
						.plusMonths(2))
				.build();
		return userRepository.save(user);
	}

	public Optional<User> getByUsername(String username) {
		return userRepository.findByUsername(username);
	}

	public void lockUser(Long userId) {
		userRepository.findById(userId)
				.ifPresent(user -> {
					user.setLocked(true);
					userRepository.save(user);
				});
	}

	public void unlockUser(Long userId) {
		userRepository.findById(userId)
				.ifPresent(user -> {
					user.setLocked(false);
					userRepository.save(user);
				});
	}

	public void activateUser(Long userId) {
		userRepository.findById(userId)
				.ifPresent(user -> {
					user.setActive(true);
					userRepository.save(user);
				});
	}

	public void deactivateUser(Long userId) {
		userRepository.findById(userId)
				.ifPresent(user -> {
					user.setActive(false);
					userRepository.save(user);
				});
	}
}
