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
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotEmpty;

@Entity
@Table(name = "roleright")
public class RoleRight extends BaseEntity {

	@NotEmpty
	@Column(length = 80)
	private String name;

	@ManyToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL, optional = false)
	private Role role;

	@OneToMany(mappedBy = "roleRight", fetch = FetchType.LAZY, orphanRemoval = true, cascade = CascadeType.ALL)
	private final Set<RoleRightContext> roleRightContexts = new HashSet<>();

	/**
	 * NEVER USE DIRECTLY, ONLY SET FOR HIBERNATE
	 */
	public RoleRight() {
	}

	public RoleRight(final String name, final Role role) {
		initCreate();
		this.name = name;
		this.role = role;
	}

	public String getName() {
		return name;
	}

	public Role getRole() {
		return role;
	}

	public Set<RoleRightContext> getRoleRightContexts() {
		return roleRightContexts;
	}

	@Override
	public String toString() {
		return role + ":" + name;
	}
}
