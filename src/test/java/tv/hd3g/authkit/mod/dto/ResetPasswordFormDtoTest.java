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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomString;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import tv.hd3g.authkit.mod.dto.validated.ResetPasswordFormDto;

class ResetPasswordFormDtoTest {

	@Mock
	private Password password;

	private ResetPasswordFormDto resetPasswordFormDto;

	@BeforeEach
	public void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		resetPasswordFormDto = new ResetPasswordFormDto();
	}

	@Test
	void testGetNewuserpassword() {
		assertNull(resetPasswordFormDto.getNewuserpassword());
	}

	@Test
	void testSetNewuserpassword() {
		resetPasswordFormDto.setNewuserpassword(password);
		assertEquals(password, resetPasswordFormDto.getNewuserpassword());
	}

	@Test
	void testGetNewuserpassword2() {
		assertNull(resetPasswordFormDto.getNewuserpassword2());
	}

	@Test
	void testSetNewuserpassword2() {
		resetPasswordFormDto.setNewuserpassword2(password);
		assertEquals(password, resetPasswordFormDto.getNewuserpassword2());
	}

	@Test
	void testGetSecuretoken() {
		assertNull(resetPasswordFormDto.getSecuretoken());
	}

	@Test
	void testSetSecuretoken() {
		final var securetoken = makeRandomString();
		resetPasswordFormDto.setSecuretoken(securetoken);
		assertEquals(securetoken, resetPasswordFormDto.getSecuretoken());
	}

	@Test
	void checkSamePasswordsOk() {
		resetPasswordFormDto.setNewuserpassword(password);
		resetPasswordFormDto.setNewuserpassword2(password);
		assertTrue(resetPasswordFormDto.checkSamePasswords());
	}

	@Test
	void checkSamePasswordsNok() {
		resetPasswordFormDto.setNewuserpassword(password);
		resetPasswordFormDto.setNewuserpassword2(new Password(makeRandomString()));
		assertFalse(resetPasswordFormDto.checkSamePasswords());
	}

}
