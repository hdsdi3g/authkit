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

import java.net.URI;
import java.util.Collection;
import java.util.List;

import tv.hd3g.authkit.mod.entity.Credential;
import tv.hd3g.authkit.mod.entity.User;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.BadTOTPCodeCantLoginException;

public interface TOTPService {

	/**
	 * @return base32 coded
	 */
	String makeSecret();

	URI makeURI(String secret, User user, String totpDomain);

	/**
	 * @return base64 coded
	 */
	String makeQRCode(URI uri);

	List<String> makeBackupCodes();

	void setupTOTP(String base32Secret, Collection<String> backupCodes, String userUUID);

	void checkCode(Credential credential, String stringCode) throws BadTOTPCodeCantLoginException;

	void removeTOTP(Credential credential);

	boolean isCodeIsValid(byte[] secret, String code);

}
