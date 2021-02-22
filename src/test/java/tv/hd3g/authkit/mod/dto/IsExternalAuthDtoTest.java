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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomThing;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import tv.hd3g.authkit.mod.dto.ressource.IsExternalAuthDto;
import tv.hd3g.authkit.mod.entity.Credential;
import tv.hd3g.authkit.tool.HashCodeEqualsTest;

class IsExternalAuthDtoTest extends HashCodeEqualsTest {

	private IsExternalAuthDto isExternalAuthDto;

	private String domain;

	@Mock
	private Credential credential;

	@BeforeEach
	void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		domain = makeRandomThing();
		Mockito.when(credential.getLdapdomain()).thenReturn(domain);
		isExternalAuthDto = new IsExternalAuthDto(credential);
	}

	@Test
	void testIsExternalAuthEnabled() {
		assertEquals(domain, isExternalAuthDto.getDomain());
	}

	@Test
	void testGetDomain() {
		assertTrue(isExternalAuthDto.isExternalAuthEnabled());
	}

	@Override
	protected Object[] makeSameInstances() {
		return new Object[] { new IsExternalAuthDto(credential), new IsExternalAuthDto(credential) };
	}

}
