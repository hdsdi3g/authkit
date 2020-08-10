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
package tv.hd3g.authkit.mod.dto.ressource;

import java.util.Objects;

import org.springframework.hateoas.RepresentationModel;

public class CreatedUserDto extends RepresentationModel<CreatedUserDto> {

	private final String userName;
	private final String userUUID;
	private final String realm;

	public CreatedUserDto(final String userName, final String userUUID, final String realm) {
		this.userName = userName;
		this.userUUID = userUUID;
		this.realm = realm;
	}

	public String getUuid() {
		return userUUID;
	}

	public String getUserName() {
		return userName;
	}

	public String getRealm() {
		return realm;
	}

	@Override
	public int hashCode() {
		final var prime = 31;
		var result = super.hashCode();
		result = prime * result + Objects.hash(realm, userName, userUUID);
		return result;
	}

	@Override
	public boolean equals(final Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final var other = (CreatedUserDto) obj;
		return Objects.equals(realm, other.realm) && Objects.equals(userName, other.userName) && Objects.equals(
		        userUUID, other.userUUID);
	}
}
