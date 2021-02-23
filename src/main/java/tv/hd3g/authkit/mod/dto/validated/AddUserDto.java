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

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import tv.hd3g.authkit.mod.dto.Password;

public class AddUserDto {

	@NotBlank
	@Size(min = 3, max = 80)
	private String userLogin;
	@NotNull
	private Password userPassword;

	public void setUserLogin(final String userLogin) {
		this.userLogin = userLogin;
	}

	public void setUserPassword(final Password userPassword) {
		this.userPassword = userPassword;
	}

	public String getUserLogin() {
		return sanitize(userLogin);
	}

	public Password getUserPassword() {
		return userPassword;
	}
}
