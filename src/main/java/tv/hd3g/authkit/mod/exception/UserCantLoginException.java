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

import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static javax.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static javax.servlet.http.HttpServletResponse.SC_OK;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

public abstract class UserCantLoginException extends Exception {

	protected UserCantLoginException(final int httpReturnCode) {
		this.httpReturnCode = httpReturnCode;
	}

	private final int httpReturnCode;

	public int getHttpReturnCode() {
		return httpReturnCode;
	}

	public static final class UnknownUserCantLoginException extends UserCantLoginException {
		public UnknownUserCantLoginException() {
			super(SC_UNAUTHORIZED);
		}
	}

	public static final class DisabledUserCantLoginException extends UserCantLoginException {
		public DisabledUserCantLoginException() {
			super(SC_UNAUTHORIZED);
		}
	}

	public static final class NoPasswordUserCantLoginException extends UserCantLoginException {
		public NoPasswordUserCantLoginException() {
			super(SC_BAD_REQUEST);
		}
	}

	public static final class BadPasswordUserCantLoginException extends UserCantLoginException {
		public BadPasswordUserCantLoginException() {
			super(SC_UNAUTHORIZED);
		}
	}

	public static final class BadTOTPCodeCantLoginException extends UserCantLoginException {
		public BadTOTPCodeCantLoginException() {
			super(SC_UNAUTHORIZED);
		}
	}

	public static final class BlockedUserCantLoginException extends UserCantLoginException {
		public BlockedUserCantLoginException() {
			super(SC_UNAUTHORIZED);
		}
	}

	public static final class TOTPUserCantLoginException extends UserCantLoginException {

		private final String userUUID;

		public TOTPUserCantLoginException(final String userUUID) {
			super(SC_OK);
			this.userUUID = userUUID;
		}

		public String getUserUUID() {
			return userUUID;
		}

	}

	public static final class UserMustChangePasswordException extends UserCantLoginException {
		private final String userUUID;

		public UserMustChangePasswordException(final String userUUID) {
			super(SC_OK);
			this.userUUID = userUUID;
		}

		public String getUserUUID() {
			return userUUID;
		}
	}

	public static final class ExternalAuthErrorCantLoginException extends UserCantLoginException {
		public ExternalAuthErrorCantLoginException() {
			super(SC_INTERNAL_SERVER_ERROR);
		}
	}

}
