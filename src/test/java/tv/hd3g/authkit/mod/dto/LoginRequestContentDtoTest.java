/*
 * This file is part of authkit.
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
 * Copyright (C) hdsdi3g for hd3g.tv 2021
 *
 */
package tv.hd3g.authkit.mod.dto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomString;

import javax.servlet.http.Cookie;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

class LoginRequestContentDtoTest {
	@Mock
	Cookie cookie;
	String userSessionToken;

	LoginRequestContentDto loginRequestContentDto;

	@BeforeEach
	void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		userSessionToken = makeRandomString();
		loginRequestContentDto = new LoginRequestContentDto(userSessionToken, cookie);
	}

	@AfterEach
	void end() {
		Mockito.verifyNoMoreInteractions(cookie);
	}

	@Test
	void testGetUserSessionCookie() {
		assertEquals(cookie, loginRequestContentDto.getUserSessionCookie());
	}

	@Test
	void testGetUserSessionToken() {
		assertEquals(userSessionToken, loginRequestContentDto.getUserSessionToken());
	}

	@Test
	void testLoginRequestContentDto() {
		assertThrows(NullPointerException.class, () -> new LoginRequestContentDto(userSessionToken, null));
		assertThrows(NullPointerException.class, () -> new LoginRequestContentDto(null, cookie));
	}

}
