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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomString;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import tv.hd3g.authkit.mod.dto.ressource.GroupOrRoleDto;
import tv.hd3g.authkit.mod.entity.Group;
import tv.hd3g.authkit.mod.entity.Role;
import tv.hd3g.authkit.tool.HashCodeEqualsTest;

class GroupOrRoleDtoTest extends HashCodeEqualsTest {

	private String name;
	private String description;
	private Group group;
	private Role role;

	@BeforeEach
	void init() {
		name = makeRandomString();
		description = makeRandomString();

		group = new Group(name);
		group.setDescription(description);

		role = new Role(name);
		role.setDescription(description);
	}

	@Test
	void getName() {
		var groupOrRoleDto = new GroupOrRoleDto(name, description);
		assertEquals(name, groupOrRoleDto.getName());

		groupOrRoleDto = new GroupOrRoleDto(group);
		assertEquals(name, groupOrRoleDto.getName());

		groupOrRoleDto = new GroupOrRoleDto(role);
		assertEquals(name, groupOrRoleDto.getName());
	}

	@Test
	void getDescription() {
		var groupOrRoleDto = new GroupOrRoleDto(name, description);
		assertEquals(description, groupOrRoleDto.getDescription());

		groupOrRoleDto = new GroupOrRoleDto(group);
		assertEquals(description, groupOrRoleDto.getDescription());

		groupOrRoleDto = new GroupOrRoleDto(role);
		assertEquals(description, groupOrRoleDto.getDescription());
	}

	@Override
	protected Object[] makeSameInstances() {
		return new Object[] {
		                      new GroupOrRoleDto(name, description),
		                      new GroupOrRoleDto(name, description) };
	}

}
