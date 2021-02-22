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
package tv.hd3g.authkit.mod.service;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserLogin;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserPassword;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import tv.hd3g.authkit.mod.dto.Password;
import tv.hd3g.authkit.mod.dto.validated.AddUserDto;
import tv.hd3g.authkit.mod.dto.validated.LoginFormDto;
import tv.hd3g.authkit.mod.exception.ResetWithSamePasswordException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException;
import tv.hd3g.authkit.tool.DataGenerator;

@SpringBootTest
class CmdLineServiceTest {

	@Autowired
	private CmdLineService cmdLineService;
	@Autowired
	private AuthenticationService authenticationService;
	@Mock
	private HttpServletRequest request;

	@BeforeEach
	void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		DataGenerator.setupMock(request);
	}

	@Test
	void addOrUpdateSecurityAdminUser_add() throws ResetWithSamePasswordException, UserCantLoginException {
		final var login = makeUserLogin();
		final var password = makeUserPassword();

		cmdLineService.addOrUpdateSecurityAdminUser(login, new Password(password));

		final var loginForm = new LoginFormDto();
		loginForm.setUserlogin(login);
		loginForm.setUserpassword(new Password(password));
		assertNotNull(authenticationService.userLoginRequest(request, loginForm));
	}

	@Test
	void addOrUpdateSecurityAdminUser_update() throws ResetWithSamePasswordException, UserCantLoginException {
		final var addUserDto = new AddUserDto();
		addUserDto.setUserLogin(makeUserLogin());
		addUserDto.setUserPassword(new Password(makeUserPassword()));
		authenticationService.addUser(addUserDto);

		final var password = makeUserPassword();
		cmdLineService.addOrUpdateSecurityAdminUser(addUserDto.getUserLogin(), new Password(password));

		final var loginForm = new LoginFormDto();
		loginForm.setUserlogin(addUserDto.getUserLogin());
		loginForm.setUserpassword(new Password(password));
		assertNotNull(authenticationService.userLoginRequest(request, loginForm));
	}

}
