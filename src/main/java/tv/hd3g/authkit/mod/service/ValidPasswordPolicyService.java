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

import tv.hd3g.authkit.mod.dto.Password;
import tv.hd3g.authkit.mod.dto.validated.AddUserDto;
import tv.hd3g.authkit.mod.exception.PasswordComplexityException;

public interface ValidPasswordPolicyService {

	void checkPasswordValidation(String username,
	                             Password password,
	                             PasswordValidationLevel level) throws PasswordComplexityException;

	public enum PasswordValidationLevel {
		DEFAULT,
		STRONG;
	}

	default void checkPasswordValidation(final AddUserDto addUser,
	                                     final PasswordValidationLevel level) throws PasswordComplexityException {
		checkPasswordValidation(addUser.getUserLogin(), addUser.getUserPassword(), level);
	}

}
