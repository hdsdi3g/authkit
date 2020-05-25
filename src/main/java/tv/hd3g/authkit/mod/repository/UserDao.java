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
package tv.hd3g.authkit.mod.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import tv.hd3g.authkit.mod.dto.ressource.UserDto;

public interface UserDao {

	/**
	 * @return UUID created for User
	 */
	UUID addUserCredential(String userLogin, byte[] cipherHashedPassword, String realm);

	/**
	 * @return UUID created for User
	 */
	UUID addLDAPUserCredential(String userLogin, String ldapDomain, String realm);

	void deleteUser(UUID userUUID);

	Optional<UserDto> getUserByUUID(UUID userUUID);

	List<UserDto> getUserList(int pos, int size);

	List<String> getRightsForUser(String userUUID, String clientAddr);

	boolean haveRightsForUserWithOnlyIP(String userUUID, String clientAddr);

	List<String> getContextRightsForUser(String userUUID, String clientAddr, String rightName);

	void deleteExternalUserCredential(String userName, String domain, String realm);

	boolean deleteGroup(String groupName);

}
