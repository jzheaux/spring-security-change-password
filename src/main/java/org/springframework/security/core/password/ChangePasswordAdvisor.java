package org.springframework.security.core.password;

import org.springframework.security.core.userdetails.UserDetails;

public interface ChangePasswordAdvisor {
	ChangePasswordAdvice advise(ChangePasswordAdviceRequest request);

	default ChangePasswordAdvice adviseCurrentPassword(UserDetails user, String password) {
		return advise(new ChangeCurrentPasswordAdviceRequest(user, password));
	}

	default ChangePasswordAdvice adviseUpdatedPassword(UserDetails user, String password) {
		return advise(new ChangeUpdatedPasswordAdviceRequest(user, password));
	}

	interface ChangePasswordAdviceRequest {
		UserDetails userDetails();
		String password();
	}

	record ChangeCurrentPasswordAdviceRequest(UserDetails userDetails, String password)
		implements ChangePasswordAdviceRequest {

	}

	record ChangeUpdatedPasswordAdviceRequest(UserDetails userDetails, String password)
		implements ChangePasswordAdviceRequest {

	}
}

