package org.springframework.security.core.password;

import org.springframework.security.core.userdetails.UserDetails;

public interface ChangePasswordAdvisor {

	ChangePasswordAdvice advise(UserDetails user, String password);

	default ChangePasswordAdvice adviseForUpdate(UserDetails user, String password) {
		return advise(user, password);
	}

}

