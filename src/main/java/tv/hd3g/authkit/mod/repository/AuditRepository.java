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

import java.util.Date;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import tv.hd3g.authkit.mod.entity.Audit;

@Repository
public interface AuditRepository extends JpaRepository<Audit, Long> {

	@Query("SELECT a FROM Audit a WHERE a.useruuid = ?1 AND a.created > ?2 ORDER BY a.created DESC")
	List<Audit> getByUserUUID(final String uuid, Date since);

	@Query("SELECT a FROM Audit a WHERE a.clientsourcehost = ?1 AND a.created > ?2 ORDER BY a.created DESC")
	List<Audit> getByClientsourcehost(final String clientsourcehost, Date since);

	@Query("SELECT a FROM Audit a WHERE a.eventname = ?1 AND a.created > ?2 ORDER BY a.created DESC")
	List<Audit> getByEventname(final String eventname, Date since);

	@Query("SELECT a.eventname FROM Audit a GROUP BY a.eventname")
	List<String> getAllEventnames();

	@Query("SELECT a.clientsourcehost FROM Audit a WHERE a.created > ?1 GROUP BY a.clientsourcehost, a.created ORDER BY a.created DESC")
	List<String> getLastClientsourcehosts(Date since);

	@Query("SELECT a FROM Audit a WHERE a.eventref = ?1")
	Audit getByEventref(final String eventref);

}
