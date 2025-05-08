/*
 * Copyright 2024 the original author or authors.
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

package org.example.custompage;

import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.password.PasswordManagementConfiguration;
import org.springframework.security.config.password.PasswordManagementConfigurer;
import org.springframework.security.core.password.ChangeCompromisedPasswordAdvisor;
import org.springframework.security.core.password.ChangePasswordAdvice;
import org.springframework.security.core.password.ChangePasswordAdvice.Action;
import org.springframework.security.core.password.ChangePasswordAdvisor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
@Import(PasswordManagementConfiguration.class)
public class SecurityConfig {

	private Log logger = LogFactory.getLog(getClass());

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, ApplicationContext context) throws Exception {
		// @formatter:off
		http
			.authorizeHttpRequests((authz) -> authz
				.requestMatchers("/admin/**").hasRole("ADMIN")
				.anyRequest().authenticated()
			)
			.formLogin(Customizer.withDefaults())
			.with(new PasswordManagementConfigurer<>(context), (passwords) -> passwords
				.changePasswordUrl("/change-password")
			);
		// @formatter:on
		return http.build();
	}

	@Bean
	InMemoryUserDetailsManager users() {
		String adminPassword = UUID.randomUUID().toString();
		this.logger.warn("The admin's password is: " + adminPassword);
		UserDetails compromised = User.withUsername("compromised").password("{noop}password").roles("USER").build();
		UserDetails admin = User.withUsername("admin").password("{noop}" + adminPassword).roles("ADMIN").build();
		return new InMemoryUserDetailsManager(compromised, admin);
	}

	@Bean
	ChangePasswordAdvisor changePasswordAdvisor() {
		ChangeCompromisedPasswordAdvisor compromised = new ChangeCompromisedPasswordAdvisor();
		compromised.setAction(Action.MUST_CHANGE);
		return compromised;
	}

}
