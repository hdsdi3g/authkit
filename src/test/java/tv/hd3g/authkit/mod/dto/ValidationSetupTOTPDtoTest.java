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

import tv.hd3g.authkit.mod.dto.validated.ValidationSetupTOTPDto;
import tv.hd3g.authkit.tool.DataGenerator;

class ValidationSetupTOTPDtoTest {

	private ValidationSetupTOTPDto validationSetupTOTPDto;

	private String controlToken;

	@BeforeEach
	void init() {
		validationSetupTOTPDto = new ValidationSetupTOTPDto();
		controlToken = DataGenerator.makeRandomString();
	}

	@Test
	void testGetControlToken() {
		validationSetupTOTPDto.setControlToken(controlToken);
		assertEquals(controlToken, validationSetupTOTPDto.getControlToken());
	}

	@Test
	void testSetControlToken() {
		assertNull(validationSetupTOTPDto.getControlToken());
		validationSetupTOTPDto.setControlToken(controlToken);
		assertNotNull(validationSetupTOTPDto.getControlToken());
		assertNull(validationSetupTOTPDto.getCurrentpassword());
		assertNull(validationSetupTOTPDto.getTwoauthcode());
	}
}
