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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomString;
import static tv.hd3g.authkit.tool.DataGenerator.makeUUID;

import java.util.Date;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class LoggedUserTagsTokenDtoTest {

	@Mock
	private Set<String> tags;
	private String userUUID;
	private Date date;
	private LoggedUserTagsTokenDto lutd;
	private String onlyForHost;

	@BeforeEach
	public void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		userUUID = makeUUID();
		date = new Date();
		onlyForHost = makeRandomString();
		lutd = new LoggedUserTagsTokenDto(userUUID, tags, date, false, onlyForHost);
	}

	@Test
	void testGetUserUUID() {
		assertEquals(userUUID, lutd.getUserUUID());
	}

	@Test
	void testGetTags() {
		assertEquals(tags, lutd.getTags());
	}

	@Test
	void getGetDate() {
		assertEquals(date, lutd.getTimeout());
	}

	@Test
	void getGetOnlyForHost() {
		assertEquals(onlyForHost, lutd.getOnlyForHost());
	}

	@Test
	void isFromCookie() {
		assertFalse(lutd.isFromCookie());
		lutd = new LoggedUserTagsTokenDto(userUUID, tags, date, true, onlyForHost);
		assertTrue(lutd.isFromCookie());

		lutd = new LoggedUserTagsTokenDto(userUUID, tags, date, true);
		assertTrue(lutd.isFromCookie());

		lutd = new LoggedUserTagsTokenDto(userUUID, tags, date, false);
		assertFalse(lutd.isFromCookie());
	}

}
