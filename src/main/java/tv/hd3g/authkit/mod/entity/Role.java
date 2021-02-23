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
package tv.hd3g.authkit.mod.entity;

import java.util.HashSet;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.ManyToMany;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotEmpty;

@Entity
@Table(name = "role")
public class Role extends BaseEntity {

	@NotEmpty
	@Column(length = 80)
	private String name;

	@Column(length = 255)
	private String description;

	@ManyToMany(mappedBy = "roles")
	private final Set<Group> groups = new HashSet<>();

	@OneToMany(mappedBy = "role", fetch = FetchType.LAZY, orphanRemoval = true, cascade = CascadeType.ALL)
	private final Set<RoleRight> roleRights = new HashSet<>();

	@Column(length = 140)
	private String onlyforclient;

	/**
	 * NEVER USE DIRECTLY, ONLY SET FOR HIBERNATE
	 */
	public Role() {
	}

	public Role(final String name) {
		initCreate();
		this.name = name;
	}

	public Set<Group> getGroups() {
		return groups;
	}

	public Set<RoleRight> getRoleRights() {
		return roleRights;
	}

	public String getName() {
		return name;
	}

	public void setName(final String name) {
		this.name = name;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(final String description) {
		this.description = description;
	}

	public void setOnlyforclient(final String onlyforclient) {
		this.onlyforclient = onlyforclient;
	}

	public String getOnlyforclient() {
		return onlyforclient;
	}

	@Override
	public String toString() {
		return name;
	}

}
