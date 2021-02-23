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
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotEmpty;

@Entity
@Table(name = "groupp")
public class Group extends BaseEntity {

	@NotEmpty
	@Column(length = 80)
	private String name;

	@Column(length = 255)
	private String description;

	@ManyToMany(cascade = { CascadeType.DETACH, CascadeType.MERGE, CascadeType.REFRESH, CascadeType.PERSIST })
	@JoinTable(
	           name = "grouprole",
	           joinColumns = { @JoinColumn(name = "group_id") },
	           inverseJoinColumns = { @JoinColumn(name = "role_id") })
	private final Set<Role> roles = new HashSet<>();

	@ManyToMany(mappedBy = "groups")
	private final Set<User> users = new HashSet<>();

	/**
	 * NEVER USE DIRECTLY, ONLY SET FOR HIBERNATE
	 */
	public Group() {
	}

	public Group(final String name) {
		initCreate();
		this.name = name;
	}

	public Set<Role> getRoles() {
		return roles;
	}

	public Set<User> getUsers() {
		return users;
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

}
