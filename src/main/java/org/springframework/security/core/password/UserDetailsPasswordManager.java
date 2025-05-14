package org.springframework.security.core.password;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;

public interface UserDetailsPasswordManager extends UserDetailsPasswordService {

	/**
	 * Update the password and remove any related password advice
	 * @param user the user to modify the password for
	 * @param newPassword the password to change to, encoded by the configured
	 * {@code PasswordEncoder}
	 * @return the updated {@link UserDetails}
	 */
	@Override
	UserDetails updatePassword(UserDetails user, String newPassword);

	ChangePasswordAdvice loadPasswordAdvice(UserDetails user);

	void savePasswordAdvice(UserDetails user, ChangePasswordAdvice advice);

	void removePasswordAdvice(UserDetails user);
}
