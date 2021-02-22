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
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomString;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class ExternalAuthUserDtoTest {

	private String login;
	private String domain;
	private String userLongName;
	private String userEmail;
	@Mock
	private List<String> groups;

	private ExternalAuthUserDto ldapUserDto;

	@BeforeEach
	public void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		login = makeRandomString();
		domain = makeRandomString();
		userLongName = makeRandomString();
		userEmail = makeRandomString();

		ldapUserDto = new ExternalAuthUserDto(login, domain, userLongName, userEmail, groups);
	}

	@Test
	void testGetLogin() {
		assertEquals(login, ldapUserDto.getLogin());
	}

	@Test
	void testGetDomain() {
		assertEquals(domain, ldapUserDto.getDomain());
	}

	@Test
	void testGetUserLongName() {
		assertEquals(userLongName, ldapUserDto.getUserLongName());
	}

	@Test
	void testGetUserEmail() {
		assertEquals(userEmail, ldapUserDto.getUserEmail());
	}

	@Test
	void testGetGroups() {
		assertEquals(groups, ldapUserDto.getGroups());
	}
}
