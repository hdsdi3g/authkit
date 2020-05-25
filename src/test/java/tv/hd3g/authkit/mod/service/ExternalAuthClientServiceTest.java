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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserLogin;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserPassword;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import tv.hd3g.authkit.mod.dto.ExternalAuthUserDto;
import tv.hd3g.authkit.mod.dto.Password;
import tv.hd3g.authkit.mod.exception.UserCantLoginException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.BadPasswordUserCantLoginException;
import tv.hd3g.authkit.tool.DataGenerator;

@SpringBootTest
class ExternalAuthClientServiceTest {

	@Autowired
	private ExternalAuthClientService externalAuthService;

	@Value("${authkit.ldaptest.simpleUserName:}")
	private String simpleUserName;
	@Value("${authkit.ldaptest.simpleUserPassword:}")
	private String simpleUserPassword;
	@Value("${authkit.ldaptest.simpleUserEmail:}")
	private String simpleUserEmail;
	@Value("${authkit.ldaptest.simpleUserLongName:}")
	private String simpleUserLongName;
	@Value("${authkit.ldaptest.domain:}")
	private String domain;
	@Value("${authkit.ldaptest.simpleUserSecurGroup:}")
	private String simpleUserSecurGroup;
	@Value("${authkit.ldaptest.simpleUserDistrGroup:}")
	private String simpleUserDistrGroup;

	private void checkGroups(final ExternalAuthUserDto ldapUser) {
		if (simpleUserSecurGroup != null && simpleUserSecurGroup.isEmpty() == false) {
			assertTrue(ldapUser.getGroups().contains(simpleUserSecurGroup));
		}
		if (simpleUserDistrGroup != null && simpleUserDistrGroup.isEmpty() == false) {
			assertTrue(ldapUser.getGroups().contains(simpleUserDistrGroup));
		}
	}

	@Test
	void testLogonUserDomain() throws UserCantLoginException {
		if (simpleUserName == null || simpleUserName.isBlank()) {
			return;
		}
		final var ldapUser = externalAuthService.logonUser(
		        simpleUserName, new Password(simpleUserPassword), domain);
		assertEquals(simpleUserName, ldapUser.getLogin());
		assertEquals(simpleUserLongName, ldapUser.getUserLongName());
		assertEquals(simpleUserEmail, ldapUser.getUserEmail());
		assertEquals(domain, ldapUser.getDomain());
		checkGroups(ldapUser);
	}

	@Test
	void testLogonUser() throws UserCantLoginException {
		if (simpleUserName == null || simpleUserName.isBlank()) {
			return;
		}
		final var ldapUser = externalAuthService.logonUser(simpleUserName, new Password(simpleUserPassword));
		assertEquals(simpleUserName, ldapUser.getLogin());
		assertEquals(simpleUserLongName, ldapUser.getUserLongName());
		assertEquals(simpleUserEmail, ldapUser.getUserEmail());
		assertEquals(domain, ldapUser.getDomain());
		checkGroups(ldapUser);
	}

	@Test
	void testLogonUser_badUser() throws UserCantLoginException {
		if (simpleUserName == null || simpleUserName.isBlank()) {
			return;
		}
		assertThrows(BadPasswordUserCantLoginException.class, () -> {
			externalAuthService.logonUser(makeUserLogin(), new Password(simpleUserPassword));
		});
	}

	@Test
	void testLogonUser_badPassword() throws UserCantLoginException {
		if (simpleUserName == null || simpleUserName.isBlank()) {
			return;
		}
		assertThrows(BadPasswordUserCantLoginException.class, () -> {
			externalAuthService.logonUser(simpleUserName, new Password(makeUserPassword()));
		});
	}

	@Test
	void testIsLDAPAvailable() {
		if (simpleUserName == null || simpleUserName.isBlank()) {
			return;
		}
		assertTrue(externalAuthService.isAvailable());
	}

	@Test
	void testIsIPCanTryToCreateExternalUserAccountInetAddress() throws UnknownHostException {
		if (simpleUserName == null || simpleUserName.isBlank()) {
			return;
		}
		assertFalse(externalAuthService.isIPAllowedToCreateUserAccount(DataGenerator.makeRandomIPv4(), domain));
		assertFalse(externalAuthService.isIPAllowedToCreateUserAccount(DataGenerator.makeRandomIPv6(), domain));
		assertTrue(externalAuthService.isIPAllowedToCreateUserAccount(InetAddress.getByName("192.168.5.9"), domain));
		assertTrue(externalAuthService.isIPAllowedToCreateUserAccount(InetAddress.getByName("172.16.0.20"), domain));
	}

	@Test
	void testIsIPCanTryToCreateExternalUserAccountInetAddressString() throws UnknownHostException {
		if (simpleUserName == null || simpleUserName.isBlank()) {
			return;
		}
		assertFalse(externalAuthService.isIPAllowedToCreateUserAccount(DataGenerator.makeRandomIPv4()));
		assertFalse(externalAuthService.isIPAllowedToCreateUserAccount(DataGenerator.makeRandomIPv6()));
		assertTrue(externalAuthService.isIPAllowedToCreateUserAccount(InetAddress.getByName("192.168.50.4")));
		assertTrue(externalAuthService.isIPAllowedToCreateUserAccount(InetAddress.getByName("172.16.0.240")));
	}
}
