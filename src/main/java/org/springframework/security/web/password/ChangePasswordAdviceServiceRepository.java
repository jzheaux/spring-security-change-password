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

package org.springframework.security.web.password;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.password.ChangePasswordAdvice;
import org.springframework.security.core.password.ChangePasswordAdviceService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

public final class ChangePasswordAdviceServiceRepository implements ChangePasswordAdviceRepository {
	private final ChangePasswordAdviceService changePasswordAdviceService;

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();

	public ChangePasswordAdviceServiceRepository(ChangePasswordAdviceService changePasswordAdviceService) {
		Assert.notNull(changePasswordAdviceService, "changePasswordAdviceService cannot be null");
		this.changePasswordAdviceService = changePasswordAdviceService;
	}

	@Override
	public ChangePasswordAdvice loadPasswordAdvice(HttpServletRequest request) {
		UserDetails user = getUser();
		if (user == null) {
			return ChangePasswordAdvice.keep();
		}
		ChangePasswordAdvice advice = this.changePasswordAdviceService.loadPasswordAdvice(user);
		return (advice != null) ? advice : ChangePasswordAdvice.keep();
	}

	@Override
	public void savePasswordAdvice(HttpServletRequest request, HttpServletResponse response, ChangePasswordAdvice advice) {
		UserDetails user = getUser();
		Assert.notNull(user, "could not find user and so cannot save advice");
		if (advice == null) {
			this.changePasswordAdviceService.removePasswordAdvice(user);
			return;
		}
		if (ChangePasswordAdvice.keep().equals(advice)) {
			this.changePasswordAdviceService.removePasswordAdvice(user);
			return;
		}
		this.changePasswordAdviceService.savePasswordAdvice(user, advice);
	}

	@Override
	public void removePasswordAdvice(HttpServletRequest request, HttpServletResponse response) {
		UserDetails user = getUser();
		Assert.notNull(user, "could not find user and so cannot save advice");
		this.changePasswordAdviceService.removePasswordAdvice(user);
	}

	private UserDetails getUser() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			return null;
		}
		if (!(authentication.getPrincipal() instanceof UserDetails user)) {
			return null;
		}
		return user;
	}

	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}
}
