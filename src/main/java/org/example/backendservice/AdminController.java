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

package org.example.backendservice;

import java.net.URI;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.password.ChangePasswordAdvice;
import org.springframework.security.core.password.ChangePasswordAdvice.Action;
import org.springframework.security.core.password.ChangePasswordAdviceService;
import org.springframework.security.core.password.ChangePasswordReason;
import org.springframework.security.core.password.SimpleChangePasswordAdvice;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/admin/passwords")
@RestController
public class AdminController {
	private final UserDetailsManager users;
	private final ChangePasswordAdviceService advice;

	public AdminController(UserDetailsManager users, ChangePasswordAdviceService advice) {
		this.users = users;
		this.advice = advice;
	}

	@GetMapping("/advice/{username}")
	public ResponseEntity<ChangePasswordAdvice> requireChangePassword(@PathVariable("username") String username) {
		UserDetails user = this.users.loadUserByUsername(username);
		if (user == null) {
			return ResponseEntity.notFound().build();
		}
		ChangePasswordAdvice advice = this.advice.loadPasswordAdvice(user);
		return ResponseEntity.ok(advice);
	}

	@PostMapping(value="/expire/{username}")
	public ResponseEntity<ChangePasswordAdvice> expirePassword(@PathVariable("username") String username) {
		UserDetails user = this.users.loadUserByUsername(username);
		if (user == null) {
			return ResponseEntity.notFound().build();
		}
		ChangePasswordAdvice advice = new SimpleChangePasswordAdvice(Action.MUST_CHANGE, ChangePasswordReason.EXPIRED);
		this.advice.savePasswordAdvice(user, advice);
		URI uri = URI.create("/admin/passwords/advice/" + username);
		return ResponseEntity.created(uri).body(advice);
	}

	@PostMapping("/change")
	public ResponseEntity<?> changePassword(ChangePassword change) {
		this.users.changePassword(null, change.password());
		return ResponseEntity.ok().build();
	}

	public record ChangePassword(String username, String password) {

	}
}
