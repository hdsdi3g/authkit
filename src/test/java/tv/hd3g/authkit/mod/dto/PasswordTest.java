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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomThing;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserPassword;

import java.util.stream.IntStream;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import tv.hd3g.authkit.mod.exception.PasswordComplexityException;
import tv.hd3g.authkit.mod.exception.PasswordComplexityException.PasswordTooShortException;
import tv.hd3g.authkit.mod.exception.PasswordComplexityException.PasswordTooSimpleException;
import tv.hd3g.authkit.tool.HashCodeEqualsTest;

class PasswordTest extends HashCodeEqualsTest {

	private Password password;
	private String passwordValue;

	@BeforeEach
	void init() {
		passwordValue = makeUserPassword();
		password = new Password(passwordValue);
	}

	@Test
	void toStringBeforeReset() {
		final String rawValue = password.toString();
		assertEquals(StringUtils.repeat("*", passwordValue.length()), rawValue);
	}

	@Test
	void toStringAfterReset() {
		password.reset();
		final String rawValue = password.toString();
		assertEquals(StringUtils.repeat("*", passwordValue.length()), rawValue);
	}

	@Test
	void charAtBeforeReset() {
		IntStream.range(0, passwordValue.length()).forEach(i -> {
			assertEquals(passwordValue.charAt(i), password.charAt(i));
		});
	}

	@Test
	void length() {
		assertEquals(passwordValue.length(), password.length());
		password.reset();
		assertEquals(passwordValue.length(), password.length());
	}

	@Test
	void charAtAfterReset() {
		password.reset();
		assertThrows(IndexOutOfBoundsException.class, () -> {
			password.charAt(0);
		});
	}

	@Test
	void subSequenceBeforeReset() {
		final CharSequence sub = password.subSequence(0, passwordValue.length());
		password.reset();
		assertTrue(passwordValue.contentEquals(sub));
	}

	@Test
	void subSequenceAfterReset() {
		password.reset();
		assertThrows(IllegalStateException.class, () -> {
			password.subSequence(0, 1);
		});
	}

	@Test
	void duplicate() {
		final var p2 = password.duplicate();
		final CharSequence sub = p2.subSequence(0, p2.length());
		p2.reset();
		assertTrue(passwordValue.contentEquals(sub));
	}

	@Override
	protected Object[] makeSameInstances() {
		return new Object[] { new Password(passwordValue), new Password(passwordValue) };
	}

	@Test
	void equalsInsensitive() {
		assertTrue(Password.equalsInsensitive("".toCharArray(), "".toCharArray()));
		assertTrue(Password.equalsInsensitive("A".toCharArray(), "a".toCharArray()));
		assertTrue(Password.equalsInsensitive("AaBb Cc é".toCharArray(), "AABB CC é".toCharArray()));
		assertFalse(Password.equalsInsensitive("AaBb".toCharArray(), "Bb".toCharArray()));
		assertFalse(Password.equalsInsensitive(" ".toCharArray(), "".toCharArray()));
		assertFalse(Password.equalsInsensitive("A".toCharArray(), "B".toCharArray()));
	}

	@Test
	void contain() {
		assertFalse(password.contain(""));
		assertFalse(password.contain(makeUserPassword()));
		assertFalse(password.contain(passwordValue + passwordValue));
		assertTrue(password.contain(passwordValue));
		assertTrue(password.contain(passwordValue.toUpperCase()));
		assertTrue(password.contain(passwordValue.toLowerCase()));

		assertTrue(password.contain(passwordValue.substring(5)));
		assertTrue(password.contain(passwordValue.substring(3, 5)));
		assertTrue(password.contain(passwordValue.substring(0, 5)));

		/**
		 * Specific ascii test
		 */
		final var thing = makeRandomThing().toUpperCase();
		final var p = new Password(thing);
		assertTrue(p.contain(thing.toLowerCase()));
	}

	@Test
	void checkSomeComplexity() throws PasswordComplexityException {
		Password.checkSomeComplexity(4, false, "aB76".toCharArray());
		Password.checkSomeComplexity(4, true, "Ab7!".toCharArray());
		Password.checkSomeComplexity(4, false, "Aqzsed".toCharArray());

		assertThrows(PasswordTooSimpleException.class, () -> {
			Password.checkSomeComplexity(4, false, "AQZS".toCharArray());
		});
		assertThrows(PasswordTooSimpleException.class, () -> {
			Password.checkSomeComplexity(4, false, "azqs".toCharArray());
		});
		assertThrows(PasswordTooShortException.class, () -> {
			Password.checkSomeComplexity(4, false, "aF".toCharArray());
		});
		assertThrows(PasswordTooShortException.class, () -> {
			Password.checkSomeComplexity(4, false, "a     F".toCharArray());
		});
		assertThrows(PasswordTooShortException.class, () -> {
			Password.checkSomeComplexity(4, false, "      aF".toCharArray());
		});
		assertThrows(PasswordTooShortException.class, () -> {
			Password.checkSomeComplexity(4, false, "aF      ".toCharArray());
		});
		assertThrows(PasswordTooSimpleException.class, () -> {
			Password.checkSomeComplexity(4, true, "AzQs".toCharArray());
		});
		assertThrows(PasswordTooSimpleException.class, () -> {
			Password.checkSomeComplexity(4, false, "AbCd".toCharArray());
		});
	}

	@Test
	void containCharArray() throws PasswordComplexityException {
		assertTrue(Password.containCharArray("AbCd".toCharArray(), "abcdef".toCharArray()));
		assertTrue(Password.containCharArray("uioPasd".toCharArray(), "qwertyuiopasdfghj".toCharArray()));
		assertTrue(Password.containCharArray("vwxyz".toCharArray(), "pqrstuvwxyz".toCharArray()));
		assertFalse(Password.containCharArray("AzERTy1234".toCharArray(), "azertyuiopqsdfghjklmwxcvbn".toCharArray()));
	}

	@Test
	void checkComplexity() throws PasswordComplexityException {
		password.checkComplexity(4, true);
		new Password("aQz,").checkComplexity(4, true);

		assertThrows(PasswordTooShortException.class, () -> {
			password.checkComplexity(100000, true);
		});
		assertThrows(PasswordTooSimpleException.class, () -> {
			new Password("1234").checkComplexity(4, true);
		});
		assertThrows(PasswordTooSimpleException.class, () -> {
			new Password("aaaa").checkComplexity(4, true);
		});
		assertThrows(PasswordTooSimpleException.class, () -> {
			new Password("AbCd").checkComplexity(4, true);
		});
	}

	@Test
	void checkComplexity_withTerm() throws PasswordComplexityException {
		password.checkComplexity(4, true, "aaaa");
		new Password("Aaa,").checkComplexity(4, true, "");
		new Password("aC O C O A").checkComplexity(4, false, "COCO");

		assertThrows(PasswordTooShortException.class, () -> {
			password.checkComplexity(100000, true, "");
		});
		assertThrows(PasswordTooShortException.class, () -> {
			new Password("aCOCOA").checkComplexity(4, false, "COCO");
		});
		assertThrows(PasswordTooShortException.class, () -> {
			new Password("aCOCOA").checkComplexity(4, false, "coco");
		});
		assertThrows(PasswordTooSimpleException.class, () -> {
			new Password("CoCo").checkComplexity(4, false, "coco");
		});
	}

}
