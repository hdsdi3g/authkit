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

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

import org.springframework.lang.Nullable;

import tv.hd3g.authkit.mod.dto.Password;

public class ValidationTOTPDto {

	@NotNull
	private Password currentpassword;

	/**
	 * Set only if user has set a TOTP/double auth
	 * Only 6 digits
	 */
	@Nullable
	@Pattern(regexp = "[\\d]{6}")
	private String twoauthcode;

	public void setCurrentpassword(final Password currentpassword) {
		this.currentpassword = currentpassword;
	}

	public Password getCurrentpassword() {
		return currentpassword;
	}

	public String getTwoauthcode() {
		return twoauthcode;
	}

	public void setTwoauthcode(final String twoauthcode) {
		this.twoauthcode = twoauthcode;
	}

}
