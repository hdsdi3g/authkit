/*
 * This file is part of authkit.
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
 * Copyright (C) hdsdi3g for hd3g.tv 2021
 *
 */
package tv.hd3g.authkit.mod.component;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static tv.hd3g.authkit.utility.ControllerType.REST;

import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import tv.hd3g.authkit.mod.controller.RestControllerUser;
import tv.hd3g.authkit.mod.dto.validated.AddUserDto;

@SpringBootTest
class AuthKitEndpointsListenerTest {

	@Autowired
	AuthKitEndpointsListener authKitEndpointsListener;

	@Test
	void testGetAllRights() {
		assertEquals(
		        Set.of("secureOnMethod", "SecurityAdmin", "secureOnClass", "secureOnMethodOr1", "secureOnMethodOr2"),
		        authKitEndpointsListener.getAllRights());
	}

	@Test
	void testGetAnnotatedClass() throws NoSuchMethodException, SecurityException {
		final var method = RestControllerUser.class.getMethod("addUser", AddUserDto.class);

		final var acc = authKitEndpointsListener.getAnnotatedClass(RestControllerUser.class);
		assertNotNull(acc);

		assertEquals("SecurityAdmin", acc.getAllRights().findFirst().get());
		assertEquals(REST, acc.getControllerType());

		final var audits = acc.getAudits(method);
		assertNotNull(audits);
		assertEquals(1, audits.size());
		assertTrue(audits.stream().anyMatch(audit -> "addUser".equals(audit.value())));
		assertTrue(acc.isRequireValidAuth(method));
		assertFalse(acc.isRequireRenforceCheckBefore(method));
		assertFalse(acc.isRequireRenforceCheckBefore(method));
		final var authList = acc.getRequireAuthList(method);
		assertNotNull(authList);
		assertEquals(1, authList.size());
		assertEquals("SecurityAdmin", authList.get(0).value()[0]);
	}
}
