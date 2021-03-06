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

public class ValidationSetupTOTPTestDto {
	private String currentpassword;
	private String twoauthcode;
	private String controlToken;

	public void setCurrentpassword(final String currentpassword) {
		this.currentpassword = currentpassword;
	}

	public String getCurrentpassword() {
		return currentpassword;
	}

	public String getTwoauthcode() {
		return twoauthcode;
	}

	public void setTwoauthcode(final String twoauthcode) {
		this.twoauthcode = twoauthcode;
	}

	public String getControlToken() {
		return controlToken;
	}

	public void setControlToken(final String controlToken) {
		this.controlToken = controlToken;
	}
}
