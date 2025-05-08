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

package org.example.backendservice;

import java.util.UUID;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.password.ChangePasswordAdvice;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ChangePasswordBackendServiceApplicationTests {

	@Autowired
	MockMvc mvc;

	@Autowired
	UserDetailsService users;

	@Test
	void whenAdminSetsExpiredAdviceThenUserLoginRedirectsToResetPassword() throws Exception {
		UserDetails admin = this.users.loadUserByUsername("admin");
		this.mvc.perform(get("/")
			.with(user(admin)))
			.andExpect(status().isOk());
		// change the password to a test value
		String random = UUID.randomUUID().toString();
		this.mvc.perform(post("/change-password").with(csrf())
				.with(user(admin))
				.param("newPassword", random))
			.andExpect(status().isFound())
			.andExpect(redirectedUrl("/"));
		// admin "expires" their own password
		this.mvc.perform(post("/admin/passwords/expire/admin").with(csrf())
			.with(user(admin)))
			.andExpect(status().isCreated())
			.andExpect(jsonPath("$.action").value(ChangePasswordAdvice.Action.MUST_CHANGE.toString()));
		// requests redirect to /change-password
		MvcResult result = this.mvc.perform(post("/login").with(csrf())
				.param("username", "admin")
				.param("password", random))
			.andExpect(status().isFound())
			.andExpect(redirectedUrl("/"))
			.andReturn();
		MockHttpSession session = (MockHttpSession) result.getRequest().getSession();
		this.mvc.perform(get("/").session(session))
			.andExpect(status().isFound())
			.andExpect(redirectedUrl("/change-password"));
		// reset the password to update
		random = UUID.randomUUID().toString();
		this.mvc.perform(post("/change-password").with(csrf())
			.session(session)
			.param("newPassword", random))
			.andExpect(status().isFound())
			.andExpect(redirectedUrl("/"));
		// now we're good
		this.mvc.perform(get("/").session(session))
			.andExpect(status().isOk());
	}

	@Test
	void whenCompromisedThenUserLoginAllowed() throws Exception {
		MvcResult result = this.mvc.perform(post("/login").with(csrf())
				.param("username", "compromised")
				.param("password", "password"))
			.andExpect(status().isFound())
			.andExpect(redirectedUrl("/"))
			.andReturn();
		MockHttpSession session = (MockHttpSession) result.getRequest().getSession();
		this.mvc.perform(get("/").session(session))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("COMPROMISED")));
	}

}
