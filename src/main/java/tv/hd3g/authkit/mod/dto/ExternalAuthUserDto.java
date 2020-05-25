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

import java.util.List;

public class ExternalAuthUserDto {

	private final String login;
	private final String domain;
	private final String userLongName;
	private final String userEmail;
	private final List<String> groups;

	public ExternalAuthUserDto(final String login,
	                           final String domain,
	                           final String userLongName,
	                           final String userEmail,
	                           final List<String> groups) {
		this.login = login;
		this.domain = domain;
		this.userLongName = userLongName;
		this.userEmail = userEmail;
		this.groups = groups;
	}

	public String getLogin() {
		return login;
	}

	public String getDomain() {
		return domain;
	}

	public String getUserLongName() {
		return userLongName;
	}

	public String getUserEmail() {
		return userEmail;
	}

	public List<String> getGroups() {
		return groups;
	}
}
