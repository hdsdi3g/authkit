/*
 * This file is part of AuthKit.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * Copyright (C) hdsdi3g for hd3g.tv 2019
 *
 */
package tv.hd3g.authkit.mod.component;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static tv.hd3g.authkit.mod.component.SecurityAdminAccountCmdLineCreator.AUTHKIT_NEWADMIN_ENVKEY;
import static tv.hd3g.authkit.mod.component.SecurityAdminAccountCmdLineCreator.AUTHKIT_PASSWORD_ENVKEY;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserLogin;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserPassword;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.test.context.SpringBootTest;

import tv.hd3g.authkit.mod.dto.Password;
import tv.hd3g.authkit.mod.dto.validated.AddUserDto;
import tv.hd3g.authkit.mod.dto.validated.LoginFormDto;
import tv.hd3g.authkit.mod.exception.UserCantLoginException;
import tv.hd3g.authkit.mod.service.AuthenticationService;
import tv.hd3g.authkit.tool.DataGenerator;

@SpringBootTest
class SecurityAdminAccountCmdLineCreatorTest {

	@Autowired
	private SecurityAdminAccountCmdLineCreator securityAdminAccountCmdLineCreator;
	@Autowired
	private AuthenticationService authenticationService;
	@Mock
	private ApplicationArguments args;
	@Mock
	private HttpServletRequest request;

	@BeforeEach
	void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		DataGenerator.setupMock(request);
	}

	@AfterEach
	void clean() {
		System.clearProperty(AUTHKIT_NEWADMIN_ENVKEY);
		System.clearProperty(AUTHKIT_PASSWORD_ENVKEY);
	}

	@Test
	void testRun_create() throws Exception {
		final var list = List.of("create-security-admin", "dont-quit-after-done");
		Mockito.when(args.getNonOptionArgs()).thenReturn(list);

		final var login = makeUserLogin();
		final var password = makeUserPassword();
		System.setProperty(AUTHKIT_NEWADMIN_ENVKEY, login);
		System.setProperty(AUTHKIT_PASSWORD_ENVKEY, password);

		securityAdminAccountCmdLineCreator.run(args);
		checkLogin(login, password);
	}

	@Test
	void testRun_update() throws Exception {
		final var login = makeUserLogin();
		final var password = makeUserPassword();
		final var addUser = new AddUserDto();
		addUser.setUserLogin(login);
		addUser.setUserPassword(new Password(password));
		authenticationService.addUser(addUser);

		final var list = List.of("create-security-admin", "dont-quit-after-done");
		Mockito.when(args.getNonOptionArgs()).thenReturn(list);

		final var password2 = makeUserPassword();
		System.setProperty(AUTHKIT_NEWADMIN_ENVKEY, login);
		System.setProperty(AUTHKIT_PASSWORD_ENVKEY, password2);

		securityAdminAccountCmdLineCreator.run(args);
		checkLogin(login, password2);
	}

	private void checkLogin(final String login, final String password) throws UserCantLoginException {
		final var loginForm = new LoginFormDto();
		loginForm.setUserlogin(login);
		loginForm.setUserpassword(new Password(password));

		final var sessionToken = authenticationService.userLoginRequest(request, loginForm);
		assertNotNull(sessionToken);
	}

}
