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

import static java.lang.System.nanoTime;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomString;
import static tv.hd3g.authkit.tool.DataGenerator.makeUUID;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserLogin;

import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import tv.hd3g.authkit.mod.dto.ressource.UserDto;
import tv.hd3g.authkit.mod.entity.Credential;
import tv.hd3g.authkit.mod.entity.User;
import tv.hd3g.authkit.tool.HashCodeEqualsTest;

class UserDtoTest extends HashCodeEqualsTest {

	private UserDto userDto;
	private User user;
	private Credential credential;

	private Date created;
	private String uuid;
	private String login;
	private String realm;
	private String ldapDomain;
	private final boolean enabled = true;
	private final boolean mustChangePassword = true;
	private Date lastlogin;

	@BeforeEach
	void init() {
		lastlogin = new Date(nanoTime());
		uuid = makeUUID();
		login = makeUserLogin();
		realm = makeRandomString();
		ldapDomain = makeRandomString();

		user = new User();
		user.setUuid(uuid);
		created = user.getCreated();

		credential = new Credential(user, login, null, realm, enabled, mustChangePassword);
		credential.setLdapdomain(ldapDomain);
		credential.setLastlogin(lastlogin);
		credential.setTotpkey(makeUserLogin().getBytes());
		user.setCredential(credential);
		userDto = new UserDto(user);
	}

	@Test
	void testGetCreated() {
		assertEquals(created, userDto.getCreated());
	}

	@Test
	void testGetUuid() {
		assertEquals(uuid, userDto.getUuid());
	}

	@Test
	void testGetLogin() {
		assertEquals(login, userDto.getLogin());
	}

	@Test
	void testGetRealm() {
		assertEquals(realm, userDto.getRealm());
	}

	@Test
	void testIsEnabled() {
		assertTrue(userDto.isEnabled());
	}

	@Test
	void testIsTotpEnabled() {
		assertTrue(userDto.isTotpEnabled());
	}

	@Test
	void testIsMustChangePassword() {
		assertTrue(userDto.isMustChangePassword());
	}

	@Test
	void testGetLastlogin() {
		assertEquals(lastlogin, userDto.getLastlogin());
	}

	@Test
	void testGetLdapDomain() {
		assertEquals(ldapDomain, userDto.getLdapDomain());
	}

	@Override
	protected Object[] makeSameInstances() {
		return new Object[] {
		                      new UserDto(user),
		                      new UserDto(user)
		};
	}

}
