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

import org.springframework.security.core.password.ChangePasswordAdvice;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

public final class SimpleChangePasswordAdviceHandler implements ChangePasswordAdviceHandler {
	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private final String changePasswordUrl;

	private RequestCache requestCache = new NullRequestCache();
	private RequestMatcher requestMatcher = AnyRequestMatcher.INSTANCE;

	public SimpleChangePasswordAdviceHandler(String changePasswordUrl) {
		Assert.hasText(changePasswordUrl, "changePasswordUrl cannot be empty");
		this.changePasswordUrl = changePasswordUrl;
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, FilterChain chain, ChangePasswordAdvice advice)
		throws IOException, ServletException {
		if (!this.requestMatcher.matches(request)) {
			return;
		}
		if (request.getRequestURI().equals(this.changePasswordUrl)) {
			chain.doFilter(request, response);
			return;
		}
		if (advice.getAction() != ChangePasswordAdvice.Action.MUST_CHANGE) {
			chain.doFilter(request, response);
			return;
		}
		this.requestCache.saveRequest(request, response);
		this.redirectStrategy.sendRedirect(request, response, this.changePasswordUrl);
	}

	public void setRequestCache(RequestCache requestCache) {
		this.requestCache = requestCache;
	}

	public void setRequestMatcher(RequestMatcher requestMatcher) {
		this.requestMatcher = requestMatcher;
	}
}
