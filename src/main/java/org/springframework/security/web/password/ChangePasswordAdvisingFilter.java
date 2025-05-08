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

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.password.ChangePasswordAdvice;
import org.springframework.security.core.password.ChangePasswordAdviceService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

public class ChangePasswordAdvisingFilter extends OncePerRequestFilter {
	private final ChangePasswordAdviceService changePasswordAdviceService;

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();

	private ChangePasswordAdviceHandler changePasswordAdviceHandler = new SimpleChangePasswordAdviceHandler(
		DefaultChangePasswordPageGeneratingFilter.DEFAULT_CHANGE_PASSWORD_URL);

	public ChangePasswordAdvisingFilter(ChangePasswordAdviceService changePasswordAdviceService) {
		this.changePasswordAdviceService = changePasswordAdviceService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
		throws ServletException, IOException {
		Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
		if (authentication == null) {
			chain.doFilter(request, response);
			return;
		}
		if (!(authentication.getPrincipal() instanceof UserDetails user)) {
			chain.doFilter(request, response);
			return;
		}
		ChangePasswordAdvice advice = this.changePasswordAdviceService.loadPasswordAdvice(user);
		this.changePasswordAdviceHandler.handle(request, response, chain, advice);
	}

	public void setChangePasswordAdviceHandler(ChangePasswordAdviceHandler changePasswordAdviceHandler) {
		this.changePasswordAdviceHandler = changePasswordAdviceHandler;
	}

	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}
}
