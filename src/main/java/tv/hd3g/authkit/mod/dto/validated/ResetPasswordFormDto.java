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

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

import tv.hd3g.authkit.mod.dto.Password;

public class ResetPasswordFormDto {

	@NotNull
	private Password newuserpassword;
	@NotNull
	private Password newuserpassword2;
	@NotBlank
	private String securetoken;

	public Password getNewuserpassword() {
		return newuserpassword;
	}

	public Password getNewuserpassword2() {
		return newuserpassword2;
	}

	public void setNewuserpassword(final Password newuserpassword) {
		this.newuserpassword = newuserpassword;
	}

	public void setNewuserpassword2(final Password newuserpassword2) {
		this.newuserpassword2 = newuserpassword2;
	}

	public String getSecuretoken() {
		return securetoken;
	}

	public void setSecuretoken(final String securetoken) {
		this.securetoken = securetoken;
	}

	public boolean checkSamePasswords() {
		return newuserpassword.equals(newuserpassword2);
	}

}
