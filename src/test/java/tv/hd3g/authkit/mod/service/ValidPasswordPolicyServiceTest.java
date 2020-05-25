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

import static java.util.stream.Collectors.toUnmodifiableList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static tv.hd3g.authkit.mod.service.ValidPasswordPolicyService.PasswordValidationLevel.DEFAULT;
import static tv.hd3g.authkit.mod.service.ValidPasswordPolicyService.PasswordValidationLevel.STRONG;
import static tv.hd3g.authkit.mod.service.ValidPasswordPolicyServiceImpl.split;
import static tv.hd3g.authkit.mod.service.ValidPasswordPolicyServiceImpl.splitAll;
import static tv.hd3g.authkit.mod.service.ValidPasswordPolicyServiceImpl.stupidLettersNumbers;
import static tv.hd3g.authkit.mod.service.ValidPasswordPolicyServiceImpl.stupidPasswordWords;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserBadPassword;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserLogin;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserPassword;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import tv.hd3g.authkit.mod.dto.Password;
import tv.hd3g.authkit.mod.exception.PasswordComplexityException;

@SpringBootTest
class ValidPasswordPolicyServiceTest {

	@Autowired
	private ValidPasswordPolicyService validPasswordPolicy;

	private String username;

	@BeforeEach
	void init() {
		username = makeUserLogin();
	}

	@Test
	void stupidPasswordWords() {
		assertTrue(stupidPasswordWords.contains("password"));
		assertTrue(stupidPasswordWords.contains("admin"));
		assertTrue(stupidPasswordWords.contains("administrator"));
		assertTrue(stupidPasswordWords.contains("root"));
	}

	@Test
	void stupidLettersNumbers() {
		assertTrue(stupidLettersNumbers.contains("0000"));
		assertTrue(stupidLettersNumbers.contains("9999"));
		assertTrue(stupidLettersNumbers.contains("aaaa"));
		assertTrue(stupidLettersNumbers.contains("mmmm"));
		assertTrue(stupidLettersNumbers.contains("zzzz"));
		assertEquals(10 + 26, stupidLettersNumbers.size());
	}

	@Test
	void testSplit() {
		assertIterableEquals(List.of("aaa@bbb.ccc", "aaa", "bbb.ccc"), split("aaa@bbb.ccc", "@"));
		assertIterableEquals(List.of("aaa"), split("aaa", "@"));
		assertIterableEquals(List.of("aaa@bbb@ccc", "aaa", "bbb", "ccc"), split("aaa@bbb@ccc", "@"));
	}

	@Test
	void testSplitAll() {
		final var s1 = splitAll("aaa@bbb.ccc", "@", ".", "%").collect(toUnmodifiableList());
		assertTrue(s1.contains("aaa@bbb.ccc"));
		assertTrue(s1.contains("aaa"));
		assertTrue(s1.contains("bbb.ccc"));
		assertTrue(s1.contains("aaa@bbb"));
		assertTrue(s1.contains("ccc"));
		assertTrue(s1.contains("bbb"));

		final var s2 = splitAll("aaa@bbb@ccc.ddd", "@", ".").collect(toUnmodifiableList());
		assertTrue(s2.contains("aaa@bbb@ccc.ddd"));
		assertTrue(s2.contains("aaa"));
		assertTrue(s2.contains("bbb"));
		assertTrue(s2.contains("ccc"));
		assertTrue(s2.contains("ddd"));
	}

	@Test
	void testCheckPasswordValidation() throws PasswordComplexityException {
		validPasswordPolicy.checkPasswordValidation(username, new Password(makeUserPassword()), DEFAULT);
		validPasswordPolicy.checkPasswordValidation(
		        username, new Password(makeUserPassword() + makeUserPassword()), STRONG);

		final var okSimpleList = List.of(
		        "AzERTy1234",
		        "Cd VF BG Nh",
		        "AhAhAhAh",
		        "adminAhAhAhAh",
		        username + "AhAhAhAh");
		final var errSimpleList = List.of(
		        makeUserBadPassword(),
		        "aaaaaa",
		        "password",
		        "Admin987654",
		        "1234abcd",
		        username,
		        username + "Prout",
		        "azertYuiop",
		        "Prout",
		        "aAaAaAaAa0",
		        "D h    s h1",
		        "284065468740645",
		        "00000000aZ");
		final var okStrongList = List.of(
		        "AzERTyUiOp123456789,",
		        "Cd VF BG Nh dE Ju Mi Cv Ez D!",
		        "$hAhAhAhAhAhAhAhAhAh",
		        "&\"'(-_ç)=$*,;:!#¤/Az",
		        username + username + username + username + username + username + "Ah,");

		for (final var item : okSimpleList) {
			try {
				validPasswordPolicy.checkPasswordValidation(username, new Password(item), DEFAULT);
			} catch (final PasswordComplexityException e) {
				Assertions.fail(item);
			}
		}
		for (final var item : errSimpleList) {
			Assertions.assertThrows(PasswordComplexityException.class, () -> {
				validPasswordPolicy.checkPasswordValidation(username, new Password(item), DEFAULT);
			}, "For  \"" + item + "\"");
		}
		for (final var item : okSimpleList) {
			Assertions.assertThrows(PasswordComplexityException.class, () -> {
				validPasswordPolicy.checkPasswordValidation(username, new Password(item), STRONG);
			}, "For  \"" + item + "\"");
		}
		for (final var item : okStrongList) {
			try {
				validPasswordPolicy.checkPasswordValidation(username, new Password(item), STRONG);
			} catch (final PasswordComplexityException e) {
				Assertions.fail(item);
			}
		}

	}

}
