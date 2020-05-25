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

import static java.util.stream.Collectors.toUnmodifiableList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomString;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomThings;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserLogin;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import tv.hd3g.authkit.mod.dto.ressource.SetupTOTPDto;
import tv.hd3g.authkit.tool.HashCodeEqualsTest;

class SetupTOTPDtoTest extends HashCodeEqualsTest {

	private SetupTOTPDto setupTOTPDto;

	private String secret;
	private URI totpURI;
	private String qrcode;
	private List<String> backupCodes;
	private String jwtControl;

	@BeforeEach
	private void init() throws URISyntaxException {
		secret = makeRandomString();
		totpURI = new URI("fff://" + makeUserLogin() + ".com?ddd");
		qrcode = makeRandomString();
		backupCodes = makeRandomThings().limit(6).collect(toUnmodifiableList());
		jwtControl = makeRandomString();
		setupTOTPDto = new SetupTOTPDto(secret, totpURI, qrcode, backupCodes, jwtControl);
	}

	@Test
	void testGetSecret() {
		assertEquals(secret, setupTOTPDto.getSecret());
	}

	@Test
	void testGetTotpURI() {
		assertEquals(totpURI, setupTOTPDto.getTotpURI());
	}

	@Test
	void testGetQrcode() {
		assertEquals(qrcode, setupTOTPDto.getQrcode());
	}

	@Test
	void testGetBackupCodes() {
		assertEquals(backupCodes, setupTOTPDto.getBackupCodes());
	}

	@Test
	void testGetJwtControl() {
		assertEquals(jwtControl, setupTOTPDto.getJwtControl());
	}

	@Override
	protected Object[] makeSameInstances() {
		return new Object[] { new SetupTOTPDto(secret, totpURI, qrcode, backupCodes, jwtControl),
		                      new SetupTOTPDto(secret, totpURI, qrcode, backupCodes, jwtControl) };
	}

}
