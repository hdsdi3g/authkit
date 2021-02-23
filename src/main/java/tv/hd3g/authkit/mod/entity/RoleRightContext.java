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

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.validation.constraints.NotEmpty;

@Entity
@Table(name = "rolerightcontext")
public class RoleRightContext extends BaseEntity {

	@NotEmpty
	@Column(length = 80)
	private String name;

	@ManyToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL, optional = false)
	private RoleRight roleRight;

	/**
	 * NEVER USE DIRECTLY, ONLY SET FOR HIBERNATE
	 */
	public RoleRightContext() {
	}

	public RoleRightContext(final String name, final RoleRight roleRight) {
		initCreate();
		this.name = name;
		this.roleRight = roleRight;
	}

	public String getName() {
		return name;
	}

	public RoleRight getRoleRight() {
		return roleRight;
	}
}
