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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import tv.hd3g.authkit.mod.dto.Password;
import tv.hd3g.authkit.mod.exception.PasswordComplexityException;

/**
 * https://en.wikipedia.org/wiki/Password_policy#cite_ref-sp800-63B_13-0
 * Password base: https://wiki.skullsecurity.org/index.php?title=Passwords
 */
@Service
public class ValidPasswordPolicyServiceImpl implements ValidPasswordPolicyService {

	public static final List<String> stupidPasswordWords = List.of("password", "admin", "administrator", "root");
	/**
	 * 0000 1111 2222 ... dddd eeee ffff ...
	 */
	public static final List<String> stupidLettersNumbers = Collections.unmodifiableList(Stream.concat(
	        IntStream.range(0, 10).mapToObj(i -> {
		        final var array = new char[4];
		        Arrays.fill(array, String.valueOf(i).charAt(0));
		        return new String(array);
	        }), IntStream.range('a', 'z' + 1).mapToObj(i -> {
		        final var array = new char[4];
		        Arrays.fill(array, (char) i);
		        return new String(array);
	        })).collect(Collectors.toList()));

	@Value("${authkit.password_policy.min_size:8}")
	private int minSize;
	@Value("${authkit.password_policy.must_have_special_chars:false}")
	private boolean mustHaveSpecialChars;
	@Value("${authkit.password_policy.ignore_generic_terms:}")
	private String[] ignoreGenericTerms;

	@Value("${authkit.password_policy.strong.min_size:20}")
	private int strongMinSize;
	@Value("${authkit.password_policy.strong.must_have_special_chars:true}")
	private boolean strongMustHaveSpecialChars;

	/**
	 * - Will check 8 characters in (minSize/strongMinSize)
	 * - Ignore spaces in count
	 * - avoid passwords consisting of repetitive or sequential characters (e.g. ‘aaaaaa’, ‘1234abcd’)
	 * - avoid context-specific words, such as the name of the service, the username, and derivatives thereof
	 */
	@Override
	public void checkPasswordValidation(final String username,
	                                    final Password password,
	                                    final PasswordValidationLevel level) throws PasswordComplexityException {

		Stream<String> sUsernameParts = Stream.empty();
		if (level == PasswordValidationLevel.DEFAULT) {
			password.checkComplexity(minSize, mustHaveSpecialChars);
			sUsernameParts = splitAll(username.toLowerCase(), "@", "\\", "%");
		} else if (level == PasswordValidationLevel.STRONG) {
			password.checkComplexity(strongMinSize, strongMustHaveSpecialChars);
			sUsernameParts = splitAll(username.toLowerCase(), "@", "\\", "%", ".");
		}

		final var sGenericTerms = Arrays.stream(Optional.ofNullable(ignoreGenericTerms)
		        .orElse(new String[0])).map(String::toLowerCase);

		final var ignoreTermList = Stream.of(
		        sGenericTerms, sUsernameParts, stupidPasswordWords.stream(), stupidLettersNumbers.stream())
		        .reduce(Stream::concat).orElseGet(Stream::empty)
		        .distinct().collect(toUnmodifiableList());

		for (final String term : ignoreTermList) {
			if (password.contain(term)) {
				if (level == PasswordValidationLevel.DEFAULT) {
					password.checkComplexity(minSize, mustHaveSpecialChars, term);
				} else if (level == PasswordValidationLevel.STRONG) {
					password.checkComplexity(strongMinSize, strongMustHaveSpecialChars, term);
				}
			}
		}
	}

	/**
	 * Special split: if text="aaa@bbb" and what="@" to return "aaa@bbb", "aaa", "bbb"
	 * @param text source text
	 * @param what the chain/char to search
	 * @return list of splited text
	 */
	public static List<String> split(final String text, final String what) {
		final List<String> list = new ArrayList<>();
		String value = text;
		int p = -1;
		list.add(value);
		while (value.indexOf(what) > -1 && value.indexOf(what) < value.length() - 1) {
			p = value.indexOf(what);
			list.add(value.substring(0, p));
			value = value.substring(p + 1, value.length());
		}
		if (p > -1) {
			list.add(value);
		}
		return list;
	}

	/**
	 * Call split() for each what, and accumulate all.
	 */
	public static Stream<String> splitAll(final String text, final String... what) {
		final var list1 = new ArrayList<String>();
		list1.add(text);
		for (final String w : what) {
			list1.addAll(split(text, w));
		}
		final var list2 = new ArrayList<String>();
		for (final String w : what) {
			list1.forEach(t -> list2.addAll(split(t, w)));
		}

		return Stream.concat(list1.stream(), list2.stream()).distinct();
	}

}
