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

import java.util.Arrays;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.IntStream;

import org.apache.commons.lang3.StringUtils;

import de.mkammerer.argon2.Argon2;
import tv.hd3g.authkit.mod.exception.PasswordComplexityException;
import tv.hd3g.authkit.mod.exception.PasswordComplexityException.PasswordTooShortException;
import tv.hd3g.authkit.mod.exception.PasswordComplexityException.PasswordTooSimpleException;

public class Password implements CharSequence {

	private final char[] value;

	public Password(final CharSequence value) {
		Objects.requireNonNull(value, "Can't handle null passwords");
		if (value.length() == 0) {
			throw new IllegalArgumentException("Can't handle empty passwords");
		}
		this.value = new char[value.length()];
		for (int i = 0; i < value.length(); i++) {
			this.value[i] = value.charAt(i);
		}
	}

	@Override
	public String toString() {
		return StringUtils.repeat("*", value.length);
	}

	@Override
	public int length() {
		return value.length;
	}

	@Override
	public char charAt(final int index) {
		if (index >= value.length || index < 0) {
			throw new IndexOutOfBoundsException("Index: " + index);
		}
		final var current = value[index];
		if (current == '\0') {
			throw new IndexOutOfBoundsException("Index: " + index + " was read, empty value now");
		}
		return current;
	}

	private static final String REUSE_ERROR = "You can't reuse a Password object";

	@Override
	public CharSequence subSequence(final int start, final int end) {
		if (value[start] == '\0') {
			throw new IllegalStateException(REUSE_ERROR);
		}
		final StringBuilder sb = new StringBuilder(end - start);
		for (int i = start; i < end; i++) {
			sb.append(charAt(i));
		}
		return sb;
	}

	public void reset() {
		Arrays.fill(value, '\0');
	}

	public boolean verify(final Argon2 argon2, final String passwordHash) {
		if (value[0] == '\0') {
			throw new IllegalStateException(REUSE_ERROR);
		}
		final var result = argon2.verify(passwordHash, value);
		reset();
		return result;
	}

	public String hash(final Function<char[], String> hasher) {
		if (value[0] == '\0') {
			throw new IllegalStateException(REUSE_ERROR);
		}
		final var result = hasher.apply(value);
		reset();
		return result;
	}

	public Password duplicate() {
		if (value[0] == '\0') {
			throw new IllegalStateException(REUSE_ERROR);
		}
		return new Password(subSequence(0, value.length));
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(value);
		return result;
	}

	@Override
	public boolean equals(final Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final Password other = (Password) obj;
		return Arrays.equals(value, other.value);
	}

	public static boolean equalsInsensitive(final char[] l, final char[] r) {
		if (l == r) {
			return true;
		} else if (l == null || r == null) {
			return false;
		}
		return equalsInsensitive(l, 0, l.length, r, 0, r.length);
	}

	/**
	 * Checks that {@code fromIndex} and {@code toIndex} are in
	 * the range and throws an exception if they aren't.
	 * See Arrays.java (from OpenJDK)
	 */
	private static void rangeCheck(final int arrayLength, final int fromIndex, final int toIndex) {
		if (fromIndex > toIndex) {
			throw new IllegalArgumentException("fromIndex(" + fromIndex + ") > toIndex(" + toIndex + ")");
		} else if (fromIndex < 0) {
			throw new ArrayIndexOutOfBoundsException(fromIndex);
		} else if (toIndex > arrayLength) {
			throw new ArrayIndexOutOfBoundsException(toIndex);
		}
	}

	/**
	 * See Arrays.java (from OpenJDK)
	 */
	private static boolean equalsInsensitive(final char[] l,
	                                         final int lFromIndex,
	                                         final int lToIndex,
	                                         final char[] r,
	                                         final int rFromIndex,
	                                         final int rToIndex) {
		rangeCheck(l.length, lFromIndex, lToIndex);
		rangeCheck(r.length, rFromIndex, rToIndex);

		final int aLength = lToIndex - lFromIndex;
		final int bLength = rToIndex - rFromIndex;
		if (aLength != bLength) {
			return false;
		}

		/**
		 * Expect short arrays sizes, don't manage ranges.
		 */
		final var l2 = Arrays.copyOf(l, l.length);
		for (int pos = 0; pos < l2.length; pos++) {
			l2[pos] = Character.toUpperCase(l2[pos]);
		}
		final var r2 = Arrays.copyOf(r, r.length);
		for (int pos = 0; pos < r2.length; pos++) {
			r2[pos] = Character.toUpperCase(r2[pos]);
		}

		final var result = Arrays.equals(l2, lFromIndex, lToIndex, r2, rFromIndex, rToIndex);
		Arrays.fill(l2, '\0');
		Arrays.fill(r2, '\0');
		return result;
	}

	/**
	 * Don't manage complex UTF-16 chars.
	 * Don't clear term or value after use.
	 * @return true if it find term in value.
	 */
	public static boolean containCharArray(final char[] term, final char[] value) {
		if (term.length == 0 || value.length == 0) {
			return false;
		}
		if (value.length < term.length) {
			return false;
		} else if (equalsInsensitive(value, term)) {
			return true;
		}
		for (int pos = 0; pos < value.length - term.length + 1; pos++) {
			if (equalsInsensitive(value, pos, pos + term.length, term, 0, term.length)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Don't modify internal password.
	 * Don't manage complex UTF-16 chars.
	 * @return true if it find term in internal password.
	 */
	public boolean contain(final String term) {
		if (value[0] == '\0') {
			throw new IllegalStateException(REUSE_ERROR);
		}
		return containCharArray(term.toCharArray(), value);
	}

	public void checkComplexity(final int minSize,
	                            final boolean mustHaveSpecialChars,
	                            final String genericTermPresenceToIgnore) throws PasswordComplexityException {
		if (value[0] == '\0') {
			throw new IllegalStateException(REUSE_ERROR);
		}
		if (value.length < minSize) {
			throw new PasswordTooShortException("Proposed password is too short");
		}
		final var term = genericTermPresenceToIgnore.toCharArray();
		if (term == null) {
			checkComplexity(minSize, mustHaveSpecialChars);
			return;
		}
		if (equalsInsensitive(value, term)) {
			throw new PasswordTooSimpleException("Proposed password is a too generic term");
		}
		final var newLen = value.length - term.length;
		final char[] valueToTest = new char[newLen];
		for (int pos = 0; pos < newLen + 1; pos++) {
			if (equalsInsensitive(value, pos, pos + term.length, term, 0, term.length) == false) {
				continue;
			}
			if (pos == 0) {
				/**
				 * term to remove starts value
				 */
				System.arraycopy(value, term.length, valueToTest, 0, newLen);
			} else if (pos == value.length - term.length) {
				/**
				 * term to remove ends value
				 */
				System.arraycopy(value, 0, valueToTest, 0, newLen);
			} else {
				System.arraycopy(value, 0, valueToTest, 0, pos + 1);
				System.arraycopy(value, pos + term.length, valueToTest, pos, newLen - pos);
			}
			checkSomeComplexity(minSize, mustHaveSpecialChars, valueToTest);
		}
	}

	public static void checkSomeComplexity(final int minSize,
	                                       final boolean mustHaveSpecialChars,
	                                       final char[] value) throws PasswordComplexityException {

		if (IntStream.range(0, value.length).mapToObj(i -> value[i]).noneMatch(Character::isLowerCase) ||
		    IntStream.range(0, value.length).mapToObj(i -> value[i]).noneMatch(Character::isUpperCase)) {
			throw new PasswordTooSimpleException("Proposed password don't mix upper and lower case");
		}

		final var lenWOSpaces = IntStream.range(0, value.length).mapToObj(i -> value[i])
		        .filter(ch -> Character.isSpaceChar(ch) == false).count();
		if (lenWOSpaces < minSize) {
			throw new PasswordTooShortException(
			        "Spaces in proposed password are not counted for length validation constraint");
		}
		final var valueWOSpaces = new char[(int) lenWOSpaces];

		var posValueWOSpaces = 0;
		for (final char element : value) {
			if (Character.isSpaceChar(element) == false) {
				valueWOSpaces[posValueWOSpaces++] = element;
			}
		}

		if (mustHaveSpecialChars) {
			final var specialCharsPresence = IntStream.range(0, valueWOSpaces.length)
			        .mapToObj(i -> valueWOSpaces[i])
			        .anyMatch(ch -> {
				        switch (Character.getType(ch)) {
				        case Character.CONNECTOR_PUNCTUATION:
				        case Character.CURRENCY_SYMBOL:
				        case Character.DASH_PUNCTUATION:
				        case Character.ENCLOSING_MARK:
				        case Character.END_PUNCTUATION:
				        case Character.FINAL_QUOTE_PUNCTUATION:
				        case Character.INITIAL_QUOTE_PUNCTUATION:
				        case Character.MATH_SYMBOL:
				        case Character.MODIFIER_SYMBOL:
				        case Character.OTHER_PUNCTUATION:
				        case Character.OTHER_SYMBOL:
				        case Character.START_PUNCTUATION:
					        return true;
				        default:
					        return false;
				        }
			        });
			if (specialCharsPresence == false) {
				Arrays.fill(valueWOSpaces, '\0');
				throw new PasswordTooSimpleException(
				        "Proposed password must at least include a special char, for this specific account.");
			}
		}

		if (containCharArray(valueWOSpaces, "abcdefghijklmnopqrstuvwxyz".toCharArray()) ||
		    containCharArray(valueWOSpaces, "qwertyuiopasdfghjklzxcvbnm".toCharArray()) ||
		    containCharArray(valueWOSpaces, "azertyuiopqsdfghjklmwxcvbn".toCharArray())) {
			Arrays.fill(valueWOSpaces, '\0');
			throw new PasswordTooSimpleException(
			        "Proposed password can't include a too simple abcdef/qwerty string sequence.");
		}
	}

	public void checkComplexity(final int minSize,
	                            final boolean mustHaveSpecialChars) throws PasswordComplexityException {
		if (value[0] == '\0') {
			throw new IllegalStateException(REUSE_ERROR);
		}

		if (value.length < minSize) {
			throw new PasswordTooShortException("Proposed password is too short");
		}
		final char[] valueToTest = new char[value.length];
		System.arraycopy(value, 0, valueToTest, 0, value.length);
		checkSomeComplexity(minSize, mustHaveSpecialChars, valueToTest);
	}

}
