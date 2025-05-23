/*
 * Copyright 2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.core.password;

import org.springframework.security.core.password.ChangePasswordAdvice.Action;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

public final class ChangeRepeatedPasswordAdvisor implements ChangePasswordAdvisor {
	private final UserDetailsService userDetailsService;
	private PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

	private Action action = Action.MUST_CHANGE;

	public ChangeRepeatedPasswordAdvisor(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	@Override
	public ChangePasswordAdvice advise(UserDetails user, String password) {
		return null;
	}

	@Override
	public ChangePasswordAdvice adviseForUpdate(UserDetails user, String password) {
		UserDetails withPassword = this.userDetailsService.loadUserByUsername(user.getUsername());
		if (this.passwordEncoder.matches(password, withPassword.getPassword())) {
			return new SimpleChangePasswordAdvice(this.action, ChangePasswordReason.REPEATED);
		}
		return ChangePasswordAdvice.keep();
	}

	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		Assert.notNull(passwordEncoder, "passwordEncoder cannot be null");
		this.passwordEncoder = passwordEncoder;
	}

	public void setAction(Action action) {
		this.action = action;
	}
}
