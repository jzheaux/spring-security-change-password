package org.springframework.security.core.password;

import java.util.Collection;

import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.security.core.password.ChangePasswordAdvice.Action;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

public final class ChangeCompromisedPasswordAdvisor implements ChangePasswordAdvisor {
	private final CompromisedPasswordChecker pwned = new HaveIBeenPwnedRestApiPasswordChecker();

	private Action action = Action.SHOULD_CHANGE;

	@Override
	public ChangePasswordAdvice advise(UserDetails user, String password) {
		return new Advice(this.action, this.pwned.check(password));
	}

	public void setAction(Action action) {
		this.action = action;
	}

	public static final class Advice implements ChangePasswordAdvice {
		private final CompromisedPasswordDecision decision;
		private final ChangePasswordAdvice advice;

		public Advice(Action action, CompromisedPasswordDecision decision) {
			this.decision = decision;
			if (decision.isCompromised()) {
				this.advice = new SimpleChangePasswordAdvice(action, ChangePasswordReason.COMPROMISED);
			} else {
				this.advice = ChangePasswordAdvice.keep();
			}
		}

		public CompromisedPasswordDecision getDecision() {
			return this.decision;
		}

		@Override
		public Action getAction() {
			return this.advice.getAction();
		}

		@Override
		public Collection<ChangePasswordReason> getReasons() {
			return this.advice.getReasons();
		}
	}
}
