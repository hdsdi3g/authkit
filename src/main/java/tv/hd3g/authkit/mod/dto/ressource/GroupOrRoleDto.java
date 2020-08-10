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

import tv.hd3g.authkit.mod.entity.Group;
import tv.hd3g.authkit.mod.entity.Role;

public class GroupOrRoleDto extends RepresentationModel<GroupOrRoleDto> {

	private final String name;
	private final String description;

	public GroupOrRoleDto(final String name, final String description) {
		this.name = name;
		this.description = description;
	}

	public GroupOrRoleDto(final Group group) {
		name = group.getName();
		description = group.getDescription();
	}

	public GroupOrRoleDto(final Role role) {
		name = role.getName();
		description = role.getDescription();
	}

	public String getName() {
		return name;
	}

	public String getDescription() {
		return description;
	}

	@Override
	public int hashCode() {
		final var prime = 31;
		var result = super.hashCode();
		result = prime * result + Objects.hash(description, name);
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
		final var other = (GroupOrRoleDto) obj;
		return Objects.equals(description, other.description) && Objects.equals(name, other.name);
	}

}
