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

import static java.util.UUID.randomUUID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomString;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserLogin;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import tv.hd3g.authkit.mod.dto.ressource.CreatedUserDto;
import tv.hd3g.authkit.tool.HashCodeEqualsTest;

class CreatedUserDtoTest extends HashCodeEqualsTest {

	private CreatedUserDto createdUserDto;
	private String userUUID;
	private String userName;
	private String realm;

	@BeforeEach
	public void init() {
		userName = makeUserLogin();
		userUUID = randomUUID().toString();
		realm = makeRandomString();
		createdUserDto = new CreatedUserDto(userName, userUUID, realm);
	}

	@Test
	void testGetUuid() {
		assertEquals(userUUID, createdUserDto.getUuid());
	}

	@Test
	void testGetUserName() {
		assertEquals(userName, createdUserDto.getUserName());
	}

	@Test
	void testGetRealm() {
		assertEquals(realm, createdUserDto.getRealm());
	}

	@Override
	protected Object[] makeSameInstances() {
		return new Object[] {
		                      new CreatedUserDto(userName, userUUID, realm),
		                      new CreatedUserDto(userName, userUUID, realm) };
	}

}
