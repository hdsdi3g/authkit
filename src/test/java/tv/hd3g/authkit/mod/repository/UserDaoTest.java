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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomBytes;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserLogin;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import tv.hd3g.authkit.mod.entity.Totpbackupcode;

@SpringBootTest
class UserDaoTest {

	@Autowired
	private UserDao userDao;
	@Value("${authkit.realm:default}")
	private String realm;
	@Autowired
	private CredentialRepository credentialRepository;
	@Autowired
	private TotpbackupcodeRepository totpbackupcodeRepository;

	@Test
	void addUserCredential() throws Exception {
		final var userLogin = makeUserLogin();
		final var cipherHashedPassword = makeRandomBytes(20);
		final var uuid = userDao.addUserCredential(userLogin, cipherHashedPassword, realm);
		assertNotNull(uuid);
	}

	@Test
	void addLDAPUserCredential() throws Exception {
		final var userLogin = makeUserLogin();
		final var ldapDomain = makeUserLogin();
		final var uuid = userDao.addLDAPUserCredential(userLogin, ldapDomain, realm);
		assertNotNull(uuid);

		final var user = userDao.getUserByUUID(uuid).get();
		assertNotNull(user);
		assertNotNull(user.getCreated());
		assertEquals(userLogin, user.getLogin());
		assertEquals(uuid.toString(), user.getUuid());
		assertEquals(realm, user.getRealm());
		assertTrue(user.isEnabled());
		assertFalse(user.isTotpEnabled());
		assertFalse(user.isMustChangePassword());
		assertNull(user.getLastlogin());
		assertEquals(ldapDomain, user.getLdapDomain());
	}

	@Test
	void deleteUser() throws Exception {
		final var userLogin = makeUserLogin();
		final var cipherHashedPassword = makeRandomBytes(20);
		final var uuid = userDao.addUserCredential(userLogin, cipherHashedPassword, realm);
		userDao.deleteUser(uuid);

		assertFalse(userDao.getUserByUUID(uuid).isPresent());
		assertNull(credentialRepository.getByUserUUID(uuid.toString()));
	}

	@Test
	void deleteUser_withBackupCodes() throws Exception {
		final var userLogin = makeUserLogin();
		final var cipherHashedPassword = makeRandomBytes(20);
		final var uuid = userDao.addUserCredential(userLogin, cipherHashedPassword, realm);

		final var credential = credentialRepository.getByUserUUID(uuid.toString());
		totpbackupcodeRepository.save(new Totpbackupcode(credential, "123456"));
		totpbackupcodeRepository.save(new Totpbackupcode(credential, "654321"));
		assertEquals(2, totpbackupcodeRepository.getByUserUUID(uuid.toString()).size());

		userDao.deleteUser(uuid);
		assertEquals(0, totpbackupcodeRepository.getByUserUUID(uuid.toString()).size());
	}

	@Test
	void getUserByUUID() throws Exception {
		final var userLogin = makeUserLogin();
		final var uuid = userDao.addUserCredential(userLogin, makeRandomBytes(20), realm);
		final var user = userDao.getUserByUUID(uuid).get();
		assertNotNull(user);
		assertNotNull(user.getCreated());
		assertEquals(userLogin, user.getLogin());
		assertEquals(uuid.toString(), user.getUuid());
		assertEquals(realm, user.getRealm());
		assertTrue(user.isEnabled());
		assertFalse(user.isTotpEnabled());
		assertFalse(user.isMustChangePassword());
		assertNull(user.getLastlogin());
		assertNull(user.getLdapDomain());
	}

	@Test
	void getUserList() throws Exception {
		final Set<String> lastCreatedUUIDs = IntStream.range(0, 10)
		        .mapToObj(i -> userDao.addUserCredential(makeUserLogin(), makeRandomBytes(20), realm))
		        .map(UUID::toString)
		        .collect(Collectors.toUnmodifiableSet());

		final var list = userDao.getUserList(0, lastCreatedUUIDs.size());
		assertNotNull(list);
		Assertions.assertEquals(lastCreatedUUIDs.size(), list.size());

		for (final var user : list) {
			assertNotNull(user);
			assertNotNull(user.getCreated());
			assertNotNull(user.getLogin());
			assertNotNull(user.getUuid());
			assertFalse(user.getLogin().isEmpty());
			assertFalse(user.getUuid().isEmpty());
			assertEquals(realm, user.getRealm());
			assertFalse(user.isMustChangePassword());
			assertTrue(lastCreatedUUIDs.contains(user.getUuid()));
			assertNull(user.getLastlogin());
			assertNull(user.getLdapDomain());
		}
	}

}
