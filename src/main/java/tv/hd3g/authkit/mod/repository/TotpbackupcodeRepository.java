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

import java.util.Set;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import tv.hd3g.authkit.mod.entity.Credential;
import tv.hd3g.authkit.mod.entity.Totpbackupcode;

@Repository
public interface TotpbackupcodeRepository extends JpaRepository<Totpbackupcode, Long> {

	@Query("SELECT bc.code FROM Totpbackupcode bc JOIN bc.credential c JOIN c.user u WHERE u.uuid = ?1")
	Set<String> getByUserUUID(String uuid);

	@Query("SELECT bc FROM Totpbackupcode bc WHERE bc.credential = ?1")
	Set<Totpbackupcode> getByCredential(Credential c);

}
