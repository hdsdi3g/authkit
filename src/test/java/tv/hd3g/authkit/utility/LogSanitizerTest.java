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
 * Copyright (C) hdsdi3g for hd3g.tv 2020
 *
 */
package tv.hd3g.authkit.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogSanitizerTest {

	@Test
	void testSanitize() {
		assertEquals("a", LogSanitizer.sanitize("a"));
		assertEquals("A a", LogSanitizer.sanitize("A a"));
		assertEquals("A a", LogSanitizer.sanitize("A a "));
		assertEquals("A a", LogSanitizer.sanitize(" A a "));
		assertEquals("A a", LogSanitizer.sanitize("A\ta"));
		assertEquals("A a", LogSanitizer.sanitize("A\ra"));
		assertEquals("A a", LogSanitizer.sanitize("A\na"));
		assertEquals("A  a", LogSanitizer.sanitize("A\r\na"));
		assertEquals("A   a", LogSanitizer.sanitize("A\r\n\ta"));
	}
}
