package com.spring_security.config;

public enum Role {
	USER, // Regular user / customer
	ADMIN, // Full system administrator
	MODERATOR, // Can manage user content, block/report users
	MANAGER, // Can manage teams, projects, or departments
	EMPLOYEE, // Internal staff member
	SUPPORT, // Customer support staff
	DEVELOPER, // Developer with technical access
	AUDITOR, // Read-only access for auditing
	SUPER_ADMIN // Higher than ADMIN, usually system-level access
}
