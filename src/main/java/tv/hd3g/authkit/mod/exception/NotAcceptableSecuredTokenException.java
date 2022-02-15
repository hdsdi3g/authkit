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
package tv.hd3g.authkit.mod.exception;

public abstract class NotAcceptableSecuredTokenException extends Exception {

	protected NotAcceptableSecuredTokenException() {
	}

	private NotAcceptableSecuredTokenException(final String message) {
		super(message);
	}

	public static final class InvalidFormatSecuredToken extends NotAcceptableSecuredTokenException {
	}

	public static final class BrokenSecuredToken extends NotAcceptableSecuredTokenException {
	}

	public static final class ExpiredSecuredToken extends NotAcceptableSecuredTokenException {
	}

	private static class BadUseSecuredToken extends NotAcceptableSecuredTokenException {
		public BadUseSecuredToken(final String entryReal, final String entryExpected, final String reason) {
			super(reason + ": \"" + entryReal + "\" instead of \"" + entryExpected + "\"");
		}
	}

	public static final class BadUseSecuredTokenInvalidType extends BadUseSecuredToken {
		public BadUseSecuredTokenInvalidType(final String entryReal, final String entryExpected) {
			super(entryReal, entryExpected, "Invalid type");
		}
	}

	public static final class BadUseSecuredTokenInvalidIssuer extends BadUseSecuredToken {
		public BadUseSecuredTokenInvalidIssuer(final String entryReal, final String entryExpected) {
			super(entryReal, entryExpected, "Invalid issuer");
		}
	}

	public static final class BadUseSecuredTokenInvalidAudience extends BadUseSecuredToken {
		public BadUseSecuredTokenInvalidAudience(final String entryReal, final String entryExpected) {
			super(entryReal, entryExpected, "Invalid audience");
		}
	}

	public static final class BadUseSecuredTokenInvalidForm extends BadUseSecuredToken {
		public BadUseSecuredTokenInvalidForm(final String entryReal, final String entryExpected) {
			super(entryReal, entryExpected, "Invalid form name");
		}
	}

}
