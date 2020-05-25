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

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import tv.hd3g.authkit.mod.entity.RoleRight;

@Repository
public interface RoleRightRepository extends JpaRepository<RoleRight, Long> {

	// @Query("SELECT rr.name FROM RoleRight rr JOIN rr.role r WHERE r.name = ?1")
	@Query("SELECT rr.name FROM RoleRight rr WHERE rr.role.name = ?1")
	List<String> getRoleRightNamesByRoleName(String name);

	@Query("SELECT rr FROM RoleRight rr WHERE rr.name = ?2 AND rr.role.name = ?1")
	RoleRight getRoleRight(final String roleName, final String rightName);

}
