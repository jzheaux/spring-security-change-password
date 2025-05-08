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

package org.springframework.security.config.password;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.password.ChangePasswordAdviceService;
import org.springframework.security.core.password.ChangePasswordServiceAdvisor;
import org.springframework.security.core.password.DelegatingChangePasswordAdvisor;
import org.springframework.security.core.password.InMemoryChangePasswordAdviceService;
import org.springframework.security.web.password.ChangePasswordAdviceHandler;
import org.springframework.security.web.password.ChangePasswordAdviceRepository;
import org.springframework.security.web.password.ChangePasswordAdviceServiceRepository;
import org.springframework.security.web.password.ChangePasswordAdvisingFilter;
import org.springframework.security.web.password.ChangePasswordProcessingFilter;
import org.springframework.security.web.password.DefaultChangePasswordPageGeneratingFilter;
import org.springframework.security.web.password.HttpSessionChangePasswordAdviceRepository;
import org.springframework.security.web.password.SimpleChangePasswordAdviceHandler;

import org.springframework.context.ApplicationContext;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.core.password.ChangeCompromisedPasswordAdvisor;
import org.springframework.security.core.password.ChangePasswordAdvice;
import org.springframework.security.core.password.ChangePasswordAdvisor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

public final class PasswordManagementConfigurer<H extends HttpSecurityBuilder<H>>
	extends AbstractHttpConfigurer<PasswordManagementConfigurer<H>, H> {

	private final ApplicationContext context;

	public PasswordManagementConfigurer(ApplicationContext context) {
		this.context = context;
	}

	private boolean customChangePasswordPage = false;

	private String changePasswordUrl = DefaultChangePasswordPageGeneratingFilter.DEFAULT_CHANGE_PASSWORD_URL;

	private String changePasswordProcessingUrl = ChangePasswordProcessingFilter.DEFAULT_PASSWORD_CHANGE_PROCESSING_URL;

	private ChangePasswordAdviceRepository changePasswordAdviceRepository;

	private ChangePasswordAdvisor changePasswordAdvisor;

	private ChangePasswordAdviceHandler changePasswordAdviceHandler;

	private UserDetailsPasswordService userDetailsPasswordService;

	public PasswordManagementConfigurer<H> changePasswordProcessingUrl(String changePasswordProcessingUrl) {
		this.changePasswordProcessingUrl = changePasswordProcessingUrl;
		return this;
	}

	public PasswordManagementConfigurer<H> changePasswordUrl(String changePasswordUrl) {
		this.changePasswordUrl = changePasswordUrl;
		this.customChangePasswordPage = true;
		return this;
	}

	public PasswordManagementConfigurer<H> changePasswordAdviceRepository(ChangePasswordAdviceRepository changePasswordAdviceRepository) {
		this.changePasswordAdviceRepository = changePasswordAdviceRepository;
		return this;
	}

	public PasswordManagementConfigurer<H> changePasswordAdvisor(ChangePasswordAdvisor changePasswordAdvisor) {
		this.changePasswordAdvisor = changePasswordAdvisor;
		return this;
	}

	public PasswordManagementConfigurer<H> changePasswordAdviceHandler(ChangePasswordAdviceHandler changePasswordAdviceHandler) {
		this.changePasswordAdviceHandler = changePasswordAdviceHandler;
		return this;
	}

	public PasswordManagementConfigurer<H> changePasswordService(UserDetailsPasswordService changePasswordService) {
		this.userDetailsPasswordService = changePasswordService;
		return this;
	}

	@Override
	public void init(H http) throws Exception {
		ChangePasswordAdviceRepository changePasswordAdviceRepository = (this.changePasswordAdviceRepository != null) ?
			this.changePasswordAdviceRepository :
			this.context.getBeanProvider(ChangePasswordAdviceRepository.class)
				.getIfUnique(() -> {
					ChangePasswordAdviceService service = this.context.getBeanProvider(ChangePasswordAdviceService.class).getIfUnique();
					if (service == null) {
						return new HttpSessionChangePasswordAdviceRepository();
					}
					return new ChangePasswordAdviceServiceRepository(service);
				});

		ChangePasswordAdvisor changePasswordAdvisor = (this.changePasswordAdvisor != null) ?
			this.changePasswordAdvisor :
			this.context.getBeanProvider(ChangePasswordAdvisor.class)
				.getIfUnique(() -> {
					List<ChangePasswordAdvisor> advisors = new ArrayList<>();
					advisors.add(new ChangeCompromisedPasswordAdvisor());
					this.context.getBeanProvider(ChangePasswordAdviceService.class)
						.ifUnique((bean) -> advisors.add(new ChangePasswordServiceAdvisor(bean)));
					return new DelegatingChangePasswordAdvisor(advisors);
				});

		http.setSharedObject(ChangePasswordAdviceRepository.class, changePasswordAdviceRepository);
		http.setSharedObject(ChangePasswordAdvisor.class, changePasswordAdvisor);

		SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
		http.getConfigurer(FormLoginConfigurer.class)
			.successHandler((request, response, authentication) -> {
				UserDetails user = (UserDetails) authentication.getPrincipal();
				String password = request.getParameter("password");
				ChangePasswordAdvice advice = changePasswordAdvisor.adviseCurrentPassword(user, password);
				changePasswordAdviceRepository.savePasswordAdvice(request, response, advice);
				successHandler.onAuthenticationSuccess(request, response, authentication);
			});
	}

	@Override
	public void configure(H http) throws Exception {
		PasswordEncoder passwordEncoder = this.context.getBeanProvider(PasswordEncoder.class).getIfUnique(
			PasswordEncoderFactories::createDelegatingPasswordEncoder);

		ChangePasswordAdviceHandler changePasswordAdviceHandler = (this.changePasswordAdviceHandler != null) ?
			this.changePasswordAdviceHandler :
			this.context.getBeanProvider(ChangePasswordAdviceHandler.class)
				.getIfUnique(() -> new SimpleChangePasswordAdviceHandler(this.changePasswordUrl));

		UserDetailsPasswordService passwordService = (this.userDetailsPasswordService == null) ?
			this.context.getBean(UserDetailsPasswordService.class) : this.userDetailsPasswordService;

		if (!this.customChangePasswordPage) {
			DefaultChangePasswordPageGeneratingFilter page = new DefaultChangePasswordPageGeneratingFilter();
			http.addFilterBefore(page, RequestCacheAwareFilter.class);
		}

		ChangePasswordProcessingFilter processing = new ChangePasswordProcessingFilter(passwordService);
		processing.setRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher(this.changePasswordProcessingUrl));
		processing.setChangePasswordAdvisor(http.getSharedObject(ChangePasswordAdvisor.class));
		processing.setChangePasswordAdviceRepository(http.getSharedObject(ChangePasswordAdviceRepository.class));
		processing.setPasswordEncoder(passwordEncoder);
		processing.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
		http.addFilterBefore(processing, RequestCacheAwareFilter.class);

		ChangePasswordAdvisingFilter advising = new ChangePasswordAdvisingFilter();
		advising.setChangePasswordAdviceRepository(http.getSharedObject(ChangePasswordAdviceRepository.class));
		advising.setChangePasswordAdviceHandler(changePasswordAdviceHandler);
		http.addFilterBefore(advising, RequestCacheAwareFilter.class);
	}
}
