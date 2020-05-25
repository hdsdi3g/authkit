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
package tv.hd3g.authkit.tool;

import static tv.hd3g.authkit.tool.DataGenerator.makeUserLogin;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserPassword;

import tv.hd3g.authkit.mod.dto.Password;
import tv.hd3g.authkit.mod.dto.validated.AddUserDto;

public class AddUserTestDto {

	private final String userLogin;
	private final String userPassword;

	public AddUserTestDto() {
		userLogin = makeUserLogin();
		userPassword = makeUserPassword();
	}

	public String getUserLogin() {
		return userLogin;
	}

	public String getUserPassword() {
		return userPassword;
	}

	public AddUserDto makeClassicDto() {
		final var addUser = new AddUserDto();
		addUser.setUserLogin(userLogin);
		addUser.setUserPassword(new Password(userPassword));
		return addUser;
	}

}
