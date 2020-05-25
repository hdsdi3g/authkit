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

import java.util.Set;

public class SetupTOTPTokenDto {

	private final String userUUID;
	private final String secret;
	private final Set<String> backupCodes;

	public SetupTOTPTokenDto(final String userUUID, final String secret, final Set<String> backupCodes) {
		this.userUUID = userUUID;
		this.secret = secret;
		this.backupCodes = backupCodes;
	}

	public String getUserUUID() {
		return userUUID;
	}

	public String getSecret() {
		return secret;
	}

	public Set<String> getBackupCodes() {
		return backupCodes;
	}

}
