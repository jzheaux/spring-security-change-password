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

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.password.ChangePasswordAdviceMethodArgumentResolver;
import org.springframework.security.web.password.ChangePasswordAdviceRepository;
import org.springframework.security.web.password.HttpSessionChangePasswordAdviceRepository;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class PasswordManagementConfiguration {
	private ChangePasswordAdviceRepository changePasswordAdviceRepository = new HttpSessionChangePasswordAdviceRepository();

	@Bean
	WebMvcConfigurer argumentResolvers() {
		return new WebMvcConfigurer() {
			@Override
			public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
				ChangePasswordAdviceMethodArgumentResolver resolver = new ChangePasswordAdviceMethodArgumentResolver();
				resolver.setChangePasswordAdviceRepository(changePasswordAdviceRepository);
				resolvers.add(resolver);
			}
		};
	}

	@Autowired(required = false)
	public void setChangePasswordAdviceRepository(ChangePasswordAdviceRepository changePasswordAdviceRepository) {
		this.changePasswordAdviceRepository = changePasswordAdviceRepository;
	}

}
