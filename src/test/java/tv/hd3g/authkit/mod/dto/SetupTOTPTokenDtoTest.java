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

import static java.util.stream.Collectors.toUnmodifiableSet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomString;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomThings;

import java.net.URISyntaxException;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SetupTOTPTokenDtoTest {

	private SetupTOTPTokenDto setupTOTPJWTDto;
	private String userUUID;
	private String secret;
	private Set<String> backupCodes;

	@BeforeEach
	private void init() throws URISyntaxException {
		userUUID = makeRandomString();
		secret = makeRandomString();
		backupCodes = makeRandomThings().limit(6).collect(toUnmodifiableSet());
		setupTOTPJWTDto = new SetupTOTPTokenDto(userUUID, secret, backupCodes);
	}

	@Test
	void testGetUserUUID() {
		assertEquals(userUUID, setupTOTPJWTDto.getUserUUID());
	}

	@Test
	void testGetSecret() {
		assertEquals(secret, setupTOTPJWTDto.getSecret());
	}

	@Test
	void testGetBackupCodes() {
		assertEquals(backupCodes, setupTOTPJWTDto.getBackupCodes());
	}
}
