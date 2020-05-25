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

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URISyntaxException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import tv.hd3g.authkit.mod.dto.ressource.IsTOTPEnabledDto;
import tv.hd3g.authkit.mod.entity.Credential;
import tv.hd3g.authkit.tool.HashCodeEqualsTest;

class IsTOTPEnabledDtoTest extends HashCodeEqualsTest {

	private Credential credential;

	@BeforeEach
	private void init() throws URISyntaxException {
		credential = Mockito.mock(Credential.class);
		final var key = new byte[0];
		Mockito.when(credential.getTotpkey()).thenReturn(key);
	}

	@Test
	void testIsTotpEnabled() {
		final var is = new IsTOTPEnabledDto(credential);
		assertTrue(is.isTwoAuthEnabled());
	}

	@Override
	protected Object[] makeSameInstances() {
		return new Object[] { new IsTOTPEnabledDto(credential), new IsTOTPEnabledDto(credential) };
	}

}
