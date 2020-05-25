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
package tv.hd3g.authkit.mod.service;

import java.net.InetAddress;
import java.util.Optional;

import tv.hd3g.authkit.mod.dto.ExternalAuthUserDto;
import tv.hd3g.authkit.mod.dto.Password;
import tv.hd3g.authkit.mod.exception.UserCantLoginException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.ExternalAuthErrorCantLoginException;

public interface ExternalAuthClientService {

	boolean isAvailable();

	Optional<String> getDefaultDomainName();

	ExternalAuthUserDto logonUser(String login, Password password, String domain) throws UserCantLoginException;

	boolean isIPAllowedToCreateUserAccount(InetAddress address, String domain);

	default ExternalAuthUserDto logonUser(final String login, final Password password) throws UserCantLoginException {
		final var oDefaultDomain = getDefaultDomainName();
		if (oDefaultDomain.isEmpty()) {
			throw new ExternalAuthErrorCantLoginException();
		}
		return logonUser(login, password, oDefaultDomain.get());
	}

	default boolean isIPAllowedToCreateUserAccount(final InetAddress address) {
		final var oDefaultDomain = getDefaultDomainName();
		if (oDefaultDomain.isEmpty()) {
			return false;
		}
		return isIPAllowedToCreateUserAccount(address, oDefaultDomain.get());
	}

}
