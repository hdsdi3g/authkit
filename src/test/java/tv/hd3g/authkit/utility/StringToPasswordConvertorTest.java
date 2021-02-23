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
package tv.hd3g.authkit.utility;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import tv.hd3g.authkit.tool.DataGenerator;

class StringToPasswordConvertorTest {

	@Test
	void convert() {
		final var password = DataGenerator.makeUserPassword();
		final var stst = new StringToPasswordConvertor();
		assertNotNull(stst.convert(password));
		assertTrue(password.contentEquals(stst.convert(password).subSequence(0, password.length())));
	}
}
