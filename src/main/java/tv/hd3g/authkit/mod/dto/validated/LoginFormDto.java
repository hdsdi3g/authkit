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
package tv.hd3g.authkit.mod.dto.validated;

import static tv.hd3g.authkit.utility.LogSanitizer.sanitize;

import java.util.Optional;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

import tv.hd3g.authkit.mod.dto.Password;

public class LoginFormDto {

	@NotBlank
	private String userlogin;
	@NotNull
	private Password userpassword;
	@NotBlank
	private String securetoken;
	/**
	 * Short time session
	 */
	private Boolean shorttime;

	public String getUserlogin() {
		return sanitize(userlogin);
	}

	public void setUserlogin(final String userlogin) {
		this.userlogin = userlogin;
	}

	public Password getUserpassword() {
		return userpassword;
	}

	public void setUserpassword(final Password userpassword) {
		this.userpassword = userpassword;
	}

	public String getSecuretoken() {
		return securetoken;
	}

	public void setSecuretoken(final String securetoken) {
		this.securetoken = securetoken;
	}

	/**
	 * @return can be null
	 */
	public Boolean getShorttime() {
		return shorttime;
	}

	public void setShorttime(final Boolean shorttime) {
		this.shorttime = shorttime;
	}

	@Override
	public String toString() {
		final var sb = new StringBuilder();
		sb.append("userLogin: ");
		sb.append(userlogin);
		sb.append(", userPassword: ");
		sb.append(Optional.ofNullable(userpassword).map(Password::toString).orElse("<null>"));
		if (isShortSessionTime()) {
			sb.append(", short time ");
		}
		sb.append(", secureToken: ");
		sb.append(securetoken);
		return sb.toString();
	}

	public boolean isShortSessionTime() {
		return Optional.ofNullable(shorttime).orElse(false);
	}

}
