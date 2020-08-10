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

import java.util.Date;
import java.util.Objects;

import org.springframework.hateoas.RepresentationModel;

import tv.hd3g.authkit.mod.entity.User;

public class UserDto extends RepresentationModel<UserDto> {

	private final Date created;
	private final String uuid;
	private final String login;
	private final String realm;
	private final boolean enabled;
	private final boolean totpEnabled;
	private final String ldapDomain;
	private final boolean mustChangePassword;
	private final Date lastlogin;

	/**
	 * See getuser.sql and listuser.sql
	 */
	public UserDto(final User user) {
		created = user.getCreated();
		uuid = user.getUuid();
		final var c = user.getCredential();
		if (c == null) {
			login = null;
			realm = null;
			enabled = false;
			totpEnabled = false;
			ldapDomain = null;
			mustChangePassword = false;
			lastlogin = null;
			return;
		}
		login = c.getLogin();
		realm = c.getRealm();
		enabled = c.isEnabled();
		totpEnabled = c.getTotpkey() != null;
		ldapDomain = c.getLdapdomain();
		mustChangePassword = c.isMustchangepassword();
		lastlogin = c.getLastlogin();
	}

	public Date getCreated() {
		return created;
	}

	public String getUuid() {
		return uuid;
	}

	public String getLogin() {
		return login;
	}

	public String getRealm() {
		return realm;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public boolean isTotpEnabled() {
		return totpEnabled;
	}

	public boolean isMustChangePassword() {
		return mustChangePassword;
	}

	public Date getLastlogin() {
		return lastlogin;
	}

	public String getLdapDomain() {
		return ldapDomain;
	}

	@Override
	public int hashCode() {
		final var prime = 31;
		var result = super.hashCode();
		result = prime * result + Objects.hash(created, enabled, lastlogin, ldapDomain, login, mustChangePassword,
		        realm, totpEnabled, uuid);
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
		final var other = (UserDto) obj;
		return Objects.equals(created, other.created) && enabled == other.enabled && Objects.equals(lastlogin,
		        other.lastlogin) && Objects.equals(ldapDomain, other.ldapDomain) && Objects.equals(login, other.login)
		       && mustChangePassword == other.mustChangePassword && Objects.equals(realm, other.realm)
		       && totpEnabled == other.totpEnabled && Objects.equals(uuid, other.uuid);
	}

}
