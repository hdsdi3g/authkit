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
package tv.hd3g.authkit.mod.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static tv.hd3g.authkit.mod.service.CookieService.AUTH_COOKIE_NAME;
import static tv.hd3g.authkit.tool.DataGenerator.random;

import java.time.Duration;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.internal.util.MockUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import tv.hd3g.authkit.tool.DataGenerator;

@SpringBootTest
class CookieServiceTest {

	@Mock
	HttpServletRequest request;

	@Autowired
	CookieService cookieService;
	@Value("#{servletContext.contextPath}")
	String path;

	String userSessionToken;

	@BeforeEach
	void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		assertFalse(MockUtil.isMock(cookieService));
		userSessionToken = DataGenerator.makeRandomString();
	}

	@AfterEach
	void end() {
		Mockito.verifyNoMoreInteractions(request);
	}

	@Test
	void testCreateLogonCookie() {
		final var ttl = Duration.ofMillis(random.nextLong(2_000));
		final var c = cookieService.createLogonCookie(userSessionToken, ttl);

		assertEquals(AUTH_COOKIE_NAME, c.getName());
		assertEquals(userSessionToken, c.getValue());
		assertNotNull(c.getDomain());
		assertTrue(c.isHttpOnly());
		assertTrue(c.getSecure());
		assertEquals(path, c.getPath());
		assertEquals(ttl.toSeconds(), c.getMaxAge());
	}

	@Test
	void testDeleteLogonCookie() {
		final var c = cookieService.deleteLogonCookie();
		assertEquals(AUTH_COOKIE_NAME, c.getName());
		assertNull(c.getValue());
	}

	@Test
	void testGetLogonCookiePayload() {
		final var c = new Cookie(AUTH_COOKIE_NAME, userSessionToken);
		when(request.getCookies()).thenReturn(new Cookie[] { c });

		final var result = cookieService.getLogonCookiePayload(request);
		assertEquals(userSessionToken, result);

		Mockito.verify(request, Mockito.times(1)).getCookies();
	}
}
