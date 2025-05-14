package org.springframework.security.core.password;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.util.Assert;

public class InMemoryUserDetailsPasswordManager extends InMemoryUserDetailsManager
	implements UserDetailsPasswordManager {

	private final Map<String, ChangePasswordAdvice> advice = new HashMap<>();

	public InMemoryUserDetailsPasswordManager(UserDetails... users) {
		super(users);
	}

	@Override
	public UserDetails updatePassword(UserDetails user, String newPassword) {
		UserDetails updated = super.updatePassword(user, newPassword);
		removePasswordAdvice(user);
		return updated;
	}

	@Override
	public ChangePasswordAdvice loadPasswordAdvice(UserDetails user) {
		return this.advice.get(user.getUsername());
	}

	@Override
	public void savePasswordAdvice(UserDetails user, ChangePasswordAdvice advice) {
		Assert.notNull(advice, "advice must not be null; if you want to remove advice, please call removePasswordAdvice");
		this.advice.put(user.getUsername(), advice);
	}

	@Override
	public void removePasswordAdvice(UserDetails user) {
		this.advice.remove(user.getUsername());
	}
}
