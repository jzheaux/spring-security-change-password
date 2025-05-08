package org.example.customadvisor;

import org.springframework.security.core.password.ChangePasswordAdvice;
import org.springframework.security.core.password.ChangePasswordAdvisor;
import org.springframework.security.core.password.ChangePasswordReason;
import org.springframework.security.core.password.SimpleChangePasswordAdvice;
import org.springframework.stereotype.Component;

@Component
public class ChangeAngleBracketsPasswordAdvisor implements ChangePasswordAdvisor {
	@Override
	public ChangePasswordAdvice advise(ChangePasswordAdviceRequest request) {
		if (request.password().contains("<") || request.password().contains(">")) {
			return new SimpleChangePasswordAdvice(ChangePasswordAdvice.Action.MUST_CHANGE, ChangePasswordReason.UNSUPPORTED_CHARACTERS);
		}
		return ChangePasswordAdvice.keep();
	}
}
