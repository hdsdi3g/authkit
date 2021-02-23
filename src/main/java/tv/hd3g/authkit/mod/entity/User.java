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
import java.util.UUID;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.validation.constraints.NotEmpty;

@Entity
@Table(name = "user")
public class User extends BaseEntity {

	@NotEmpty
	@Column(length = 38)
	private String uuid;

	@OneToOne(mappedBy = "user", optional = true, fetch = FetchType.LAZY, orphanRemoval = true,
	          cascade = CascadeType.ALL)
	private Credential credential;

	@ManyToMany(cascade = { CascadeType.DETACH, CascadeType.MERGE, CascadeType.REFRESH, CascadeType.PERSIST })
	@JoinTable(
	           name = "usergroup",
	           joinColumns = { @JoinColumn(name = "user_id") },
	           inverseJoinColumns = { @JoinColumn(name = "group_id") })
	private final Set<Group> groups = new HashSet<>();

	/**
	 * NEVER USE DIRECTLY, ONLY SET FOR HIBERNATE
	 */
	public User() {
	}

	public User(final UUID uuid) {
		initCreate();
		this.uuid = uuid.toString();
	}

	public Set<Group> getGroups() {
		return groups;
	}

	public Credential getCredential() {
		return credential;
	}

	public String getUuid() {
		return uuid;
	}

	public void setUuid(final String uuid) {
		this.uuid = uuid;
	}

	public void setCredential(final Credential credential) {
		this.credential = credential;
	}

}
