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
package tv.hd3g.authkit.mod.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomString;

import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class CipherServiceTest {

	@Autowired
	private CipherService cipherService;

	@Test
	void cipherFromString() {
		final var text = makeRandomString();
		final var result = cipherService.cipherFromString(text);
		assertNotNull(result);
		assertTrue(result.length >= text.length());
		final var min = Math.min(result.length, text.length());
		assertFalse(Arrays.equals(text.getBytes(), 0, min, result, 0, min));
	}

	@Test
	void cipherFromData() {
		final var clearData = makeRandomString();
		final var result = cipherService.cipherFromData(clearData.getBytes());
		assertNotNull(result);
		assertTrue(result.length >= clearData.getBytes().length);
		final var min = Math.min(result.length, clearData.getBytes().length);
		assertFalse(Arrays.equals(clearData.getBytes(), 0, min, result, 0, min));
	}

	@Test
	void unCipherToString() {
		final var text = makeRandomString();
		final var crypedText = cipherService.cipherFromString(text);
		final var result = cipherService.unCipherToString(crypedText);
		assertEquals(text, result);
	}

	@Test
	void unCipherToData() {
		final var clearData = makeRandomString();
		final var crypedData = cipherService.cipherFromData(clearData.getBytes());
		final var result = cipherService.unCipherToData(crypedData);
		assertArrayEquals(clearData.getBytes(), result);
	}

	/**
	 * https://en.wikipedia.org/wiki/SHA-3#Comparison_of_SHA_functions
	 */
	@Test
	void computeSHA3FromString() {
		final var digest = cipherService.computeSHA3FromString("");
		assertEquals(
		        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
		        digest);
	}

}
