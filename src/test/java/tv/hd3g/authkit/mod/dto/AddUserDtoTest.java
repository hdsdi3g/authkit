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
package tv.hd3g.authkit.mod.dto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserLogin;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import tv.hd3g.authkit.mod.dto.validated.AddUserDto;

class AddUserDtoTest {

	private AddUserDto addUserDto;
	private String userLogin;

	@Mock
	private Password userPassword;

	@BeforeEach
	void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		userLogin = makeUserLogin();

		addUserDto = new AddUserDto();
		addUserDto.setUserLogin(userLogin);
		addUserDto.setUserPassword(userPassword);
	}

	@Test
	void setUserlogin() {
		addUserDto.setUserLogin(makeUserLogin());
		assertNotEquals(addUserDto.getUserLogin(), userLogin);
	}

	@Test
	void setUserpassword() {
		addUserDto.setUserPassword(Mockito.mock(Password.class));
		assertNotEquals(addUserDto.getUserPassword(), userPassword);
	}

	@Test
	void getUserlogin() {
		assertEquals(addUserDto.getUserLogin(), userLogin);
	}

	@Test
	void getUserpassword() {
		assertEquals(addUserDto.getUserPassword(), userPassword);
	}

}
