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

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.Lob;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

import org.hibernate.annotations.Type; // NOSONAR S1874 (https://hibernate.atlassian.net/browse/HHH-14935)

@Entity
@Table(name = "credential")
public class Credential extends BaseEntity {

	@NotBlank
	@Column(length = 80)
	private String login;

	@NotNull
	@Lob
	@Column(nullable = false, columnDefinition = "blob")
	private byte[] passwordhash;

	@NotBlank
	@Column(length = 80)
	private String realm;

	@NotNull
	@Type(type = "org.hibernate.type.NumericBooleanType") // NOSONAR S1874 (https://hibernate.atlassian.net/browse/HHH-14935)
	@Column(columnDefinition = "TINYINT")
	private boolean enabled;

	@Lob
	@Column(nullable = true, columnDefinition = "blob")
	private byte[] totpkey;

	@Column(length = 80)
	private String ldapdomain;

	@OneToMany(mappedBy = "credential", fetch = FetchType.LAZY, orphanRemoval = true, cascade = CascadeType.ALL)
	private final Set<Totpbackupcode> totpBackupCodes = new HashSet<>();

	@OneToOne(optional = false, fetch = FetchType.LAZY, cascade = CascadeType.DETACH)
	@JoinColumn(name = "user_id", nullable = false)
	private User user;

	@NotNull
	@Type(type = "org.hibernate.type.NumericBooleanType") // NOSONAR S1874 (https://hibernate.atlassian.net/browse/HHH-14935)
	@Column(columnDefinition = "TINYINT")
	private boolean mustchangepassword;

	private Date lastlogin;

	@NotNull
	private short logontrial;

	/**
	 * NEVER USE DIRECTLY, ONLY SET FOR HIBERNATE
	 */
	public Credential() {
	}

	/**
	 * Internal password user
	 */
	public Credential(final User user,
	                  final String login,
	                  final byte[] passwordhash,
	                  final String realm,
	                  final boolean enabled,
	                  final boolean mustchangepassword) {
		initCreate();
		this.user = user;
		this.login = login;
		this.passwordhash = passwordhash;
		this.realm = realm;
		this.enabled = enabled;
		this.mustchangepassword = mustchangepassword;
		logontrial = 0;
	}

	/**
	 * External LDAP user
	 */
	public Credential(final User user,
	                  final String login,
	                  final String ldapdomain,
	                  final String realm,
	                  final boolean enabled) {
		initCreate();
		this.user = user;
		this.login = login;
		this.ldapdomain = ldapdomain;
		this.realm = realm;
		this.enabled = enabled;
		mustchangepassword = false;
		passwordhash = new byte[0];
		logontrial = 0;
	}

	public User getUser() {
		return user;
	}

	public String getLogin() {
		return login;
	}

	public String getRealm() {
		return realm;
	}

	public byte[] getPasswordhash() {
		return passwordhash;
	}

	public void setPasswordhash(final byte[] passwordhash) {
		this.passwordhash = passwordhash;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(final boolean enabled) {
		this.enabled = enabled;
	}

	public byte[] getTotpkey() {
		return totpkey;
	}

	public void setTotpkey(final byte[] totpkey) {
		this.totpkey = totpkey;
	}

	public Set<Totpbackupcode> getTotpBackupCodes() {
		return totpBackupCodes;
	}

	public boolean isMustchangepassword() {
		return mustchangepassword;
	}

	public void setMustchangepassword(final boolean mustchangepassword) {
		this.mustchangepassword = mustchangepassword;
	}

	public void setLastlogin(final Date lastlogin) {
		this.lastlogin = lastlogin;
	}

	public Date getLastlogin() {
		return lastlogin;
	}

	public void setLogontrial(final int logontrial) {
		this.logontrial = (short) logontrial;
	}

	public short getLogontrial() {
		return logontrial;
	}

	public String getLdapdomain() {
		return ldapdomain;
	}

	public void setLdapdomain(final String ldapdomain) {
		this.ldapdomain = ldapdomain;
	}
}
