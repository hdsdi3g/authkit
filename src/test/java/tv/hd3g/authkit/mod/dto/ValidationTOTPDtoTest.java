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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import tv.hd3g.authkit.mod.dto.validated.ValidationTOTPDto;
import tv.hd3g.authkit.tool.DataGenerator;

class ValidationTOTPDtoTest {

	private ValidationTOTPDto validationTOTPDto;
	private Password currentPassword;
	private String twoauthcode;

	@BeforeEach
	void init() {
		validationTOTPDto = new ValidationTOTPDto();
		currentPassword = Mockito.mock(Password.class);
		twoauthcode = DataGenerator.makeRandomString();
	}

	@Test
	void testSetCurrentpassword() {
		assertNull(validationTOTPDto.getCurrentpassword());
		validationTOTPDto.setCurrentpassword(currentPassword);
		assertNotNull(validationTOTPDto.getCurrentpassword());
		assertNull(validationTOTPDto.getTwoauthcode());
	}

	@Test
	void testGetCurrentpassword() {
		validationTOTPDto.setCurrentpassword(currentPassword);
		assertEquals(currentPassword, validationTOTPDto.getCurrentpassword());
	}

	@Test
	void testGetTwoauthcode() {
		validationTOTPDto.setTwoauthcode(twoauthcode);
		assertEquals(twoauthcode, validationTOTPDto.getTwoauthcode());
	}

	@Test
	void testSetTwoauthcode() {
		assertNull(validationTOTPDto.getTwoauthcode());
		validationTOTPDto.setTwoauthcode(twoauthcode);
		assertNotNull(validationTOTPDto.getTwoauthcode());
		assertNull(validationTOTPDto.getCurrentpassword());
	}
}
