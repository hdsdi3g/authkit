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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserPassword;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import net.datafaker.Faker;
import tv.hd3g.authkit.mod.dto.validated.LoginFormDto;

class LoginFormDtoTest {

	@Mock
	private Password password;
	private String securetoken;

	private LoginFormDto loginFormDto;

	@BeforeEach
	void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		loginFormDto = new LoginFormDto();
		securetoken = makeUserPassword();
	}

	@Test
	void setUserlogin() {
		assertNull(loginFormDto.getUserlogin());
		final var name = Faker.instance().address().firstName();
		loginFormDto.setUserlogin(name);
		assertEquals(name, loginFormDto.getUserlogin());
	}

	@Test
	void getSetShorttime() {
		assertNull(loginFormDto.getShorttime());
		assertFalse(loginFormDto.isShortSessionTime());
		loginFormDto.setShorttime(true);
		assertTrue(loginFormDto.getShorttime());
		assertTrue(loginFormDto.isShortSessionTime());
	}

	@Test
	void setUserpassword() {
		assertNull(loginFormDto.getUserpassword());
		loginFormDto.setUserpassword(password);
		assertEquals(password, loginFormDto.getUserpassword());

		verify(password, never()).charAt(anyInt());
		verify(password, never()).length();
		verify(password, never()).reset();
		verify(password, never()).subSequence(anyInt(), anyInt());
	}

	@Test
	void setSecuretoken() {
		assertNull(loginFormDto.getSecuretoken());
		loginFormDto.setSecuretoken(securetoken);
		assertEquals(securetoken, loginFormDto.getSecuretoken());
	}

	@Test
	void toStringNotHavePassword() {
		loginFormDto.setUserpassword(password);
		final var passwordToString = makeUserPassword();
		Mockito.when(password.toString()).thenReturn(passwordToString);

		final var toString = loginFormDto.toString();
		assertTrue(toString.contains(passwordToString));

		// Impossible verify(password, Mockito.atLeastOnce()).toString();
		verify(password, never()).charAt(anyInt());
		verify(password, never()).length();
		verify(password, never()).reset();
		verify(password, never()).subSequence(anyInt(), anyInt());
	}

}
