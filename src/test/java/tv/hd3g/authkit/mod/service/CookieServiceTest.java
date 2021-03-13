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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static tv.hd3g.authkit.mod.service.CookieService.AUTH_COOKIE_NAME;
import static tv.hd3g.authkit.mod.service.CookieService.REDIRECT_AFTER_LOGIN_COOKIE_NAME;
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

	String randomRessource;

	@BeforeEach
	void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		assertFalse(MockUtil.isMock(cookieService));
		randomRessource = DataGenerator.makeRandomString();
	}

	@AfterEach
	void end() {
		Mockito.verifyNoMoreInteractions(request);
	}

	@Test
	void testCreateLogonCookie() {
		final var ttl = Duration.ofMillis(random.nextLong(2_000));
		final var c = cookieService.createLogonCookie(randomRessource, ttl);

		assertEquals(AUTH_COOKIE_NAME, c.getName());
		assertEquals(randomRessource, c.getValue());
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
		final var c = new Cookie(AUTH_COOKIE_NAME, randomRessource);
		when(request.getCookies()).thenReturn(new Cookie[] { c });

		final var result = cookieService.getLogonCookiePayload(request);
		assertEquals(randomRessource, result);

		verify(request, Mockito.times(1)).getCookies();
	}

	@Test
	void testCreateRedirectAfterLoginCookie() {
		final var c = cookieService.createRedirectAfterLoginCookie(randomRessource);

		assertEquals(REDIRECT_AFTER_LOGIN_COOKIE_NAME, c.getName());
		assertEquals(randomRessource, c.getValue());
		assertNotNull(c.getDomain());
		assertTrue(c.isHttpOnly());
		assertTrue(c.getSecure());
		assertEquals(path, c.getPath());
		assertEquals(3600, c.getMaxAge());
	}

	@Test
	void testDeleteRedirectAfterLoginCookie() {
		final var c = cookieService.deleteRedirectAfterLoginCookie();
		assertEquals(REDIRECT_AFTER_LOGIN_COOKIE_NAME, c.getName());
		assertNull(c.getValue());
	}

	@Test
	void testGetRedirectAfterLoginCookiePayload() {
		final var c = new Cookie(REDIRECT_AFTER_LOGIN_COOKIE_NAME, randomRessource);
		when(request.getCookies()).thenReturn(new Cookie[] { c });

		final var result = cookieService.getRedirectAfterLoginCookiePayload(request);
		assertEquals(randomRessource, result);

		verify(request, Mockito.times(1)).getCookies();
	}
}
