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

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import tv.hd3g.authkit.mod.entity.Credential;

/**
 * See https://docs.spring.io/spring-data/jpa/docs/1.5.0.RELEASE/reference/html/jpa.repositories.html
 */
@Repository
public interface CredentialRepository extends JpaRepository<Credential, Long> {

	@Query("SELECT c FROM Credential c WHERE c.realm = ?1 AND c.login = ?2 ")
	Credential getFromRealmLogin(final String realm, final String userlogin);

	@Query("SELECT c FROM Credential c JOIN c.user u WHERE u.uuid = ?1")
	Credential getByUserUUID(final String uuid);

	@Query("SELECT u.uuid FROM User u JOIN u.credential c WHERE c.realm = ?1 AND c.login = ?2 ")
	String getUUIDFromRealmLogin(final String realm, final String userlogin);

}
