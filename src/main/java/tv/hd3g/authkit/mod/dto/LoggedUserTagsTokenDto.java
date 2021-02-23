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

import java.util.Date;
import java.util.Set;

public class LoggedUserTagsTokenDto {

	private final Set<String> tags;
	private final String userUUID;
	private final Date expiration;
	private final boolean fromCookie;
	private final String onlyForHost;

	/**
	 * @param onlyForHost can be null
	 */
	public LoggedUserTagsTokenDto(final String userUUID,
	                              final Set<String> tags,
	                              final Date expiration,
	                              final boolean fromCookie,
	                              final String onlyForHost) {
		this.tags = tags;
		this.userUUID = userUUID;
		this.expiration = expiration;
		this.fromCookie = fromCookie;
		this.onlyForHost = onlyForHost;
	}

	public LoggedUserTagsTokenDto(final String userUUID,
	                              final Set<String> tags,
	                              final Date expiration,
	                              final boolean fromCookie) {
		this(userUUID, tags, expiration, fromCookie, null);
	}

	public String getUserUUID() {
		return userUUID;
	}

	public Set<String> getTags() {
		return tags;
	}

	public Date getTimeout() {
		return expiration;
	}

	/**
	 * @return can be null
	 */
	public String getOnlyForHost() {
		return onlyForHost;
	}

	public boolean isFromCookie() {
		return fromCookie;
	}
}
