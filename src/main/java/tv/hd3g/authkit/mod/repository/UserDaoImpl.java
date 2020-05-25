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

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import tv.hd3g.authkit.mod.component.SqlFileResourceHelper;
import tv.hd3g.authkit.mod.dto.ressource.UserDto;
import tv.hd3g.authkit.mod.entity.Credential;
import tv.hd3g.authkit.mod.entity.User;
import tv.hd3g.authkit.mod.exception.AuthKitException;

@Repository
public class UserDaoImpl implements UserDao {
	private static Logger log = LogManager.getLogger();

	private static final String HQL_CLIENT_ADDR = "clientAddr";

	private static final String HQL_USER_UUID = "userUUID";

	@Autowired
	@PersistenceContext
	private EntityManager entityManager;

	@Autowired
	private SqlFileResourceHelper sqlFileResourceHelper;

	@Override
	@Transactional
	public UUID addUserCredential(final String userLogin, final byte[] cipherHashedPassword, final String realm) {
		final var uuid = UUID.randomUUID();
		final var user = new User(uuid);
		final var credential = new Credential(user, userLogin, cipherHashedPassword, realm, true, false);
		entityManager.persist(user);
		entityManager.persist(credential);
		return uuid;
	}

	@Override
	@Transactional
	public UUID addLDAPUserCredential(final String userLogin, final String ldapDomain, final String realm) {
		final var uuid = UUID.randomUUID();
		final var user = new User(uuid);
		final var credential = new Credential(user, userLogin, ldapDomain, realm, true);
		entityManager.persist(user);
		entityManager.persist(credential);
		return uuid;
	}

	@Override
	@Transactional
	public void deleteUser(final UUID userUUID) {
		final var oUserToDelete = entityManager.createQuery("SELECT u FROM User u WHERE u.uuid = :userUUID", User.class)
		        .setParameter(HQL_USER_UUID, userUUID.toString())
		        .getResultStream()
		        .findFirst();

		final var userToDelete = oUserToDelete
		        .orElseThrow(() -> new AuthKitException("Can't found user with UUID " + userUUID));

		entityManager.remove(userToDelete);
	}

	@Override
	@Transactional
	public Optional<UserDto> getUserByUUID(final UUID userUUID) {
		final var sql = sqlFileResourceHelper.getSql("getuser.sql");
		return entityManager.createQuery(sql, UserDto.class)
		        .setParameter(HQL_USER_UUID, userUUID.toString())
		        .getResultStream()
		        .findFirst();
	}

	@Override
	@Transactional
	public List<UserDto> getUserList(final int pos, final int size) {
		final var sql = sqlFileResourceHelper.getSql("listuser.sql");
		return entityManager.createQuery(sql, UserDto.class)
		        .setFirstResult(pos)
		        .setMaxResults(size)
		        .getResultList();
	}

	@Override
	@Transactional
	public List<String> getRightsForUser(final String userUUID, final String clientAddr) {
		final var sql = sqlFileResourceHelper.getSql("getrightsforuser.sql");
		return entityManager.createQuery(sql, String.class)
		        .setParameter(HQL_USER_UUID, userUUID)
		        .setParameter(HQL_CLIENT_ADDR, clientAddr)
		        .getResultList();
	}

	@Override
	@Transactional
	public List<String> getContextRightsForUser(final String userUUID,
	                                            final String clientAddr,
	                                            final String rightName) {
		final var sql = sqlFileResourceHelper.getSql("getcontextrightsforuser.sql");
		return entityManager.createQuery(sql, String.class)
		        .setParameter(HQL_USER_UUID, userUUID)
		        .setParameter(HQL_CLIENT_ADDR, clientAddr)
		        .setParameter("rightName", rightName)
		        .getResultList();
	}

	@Override
	public boolean haveRightsForUserWithOnlyIP(final String userUUID, final String clientAddr) {
		final var sql = sqlFileResourceHelper.getSql("countrightsforuserwithiponly.sql");
		return entityManager.createQuery(sql, Long.class)
		        .setParameter(HQL_USER_UUID, userUUID)
		        .setParameter(HQL_CLIENT_ADDR, clientAddr)
		        .getSingleResult() > 0;
	}

	@Override
	@Transactional
	public void deleteExternalUserCredential(final String userName, final String domain, final String realm) {
		try {
			final var sql0 = "SELECT c FROM Credential c WHERE c.login = :userName AND c.ldapdomain = :domain AND c.realm = :realm";
			final var credential = entityManager.createQuery(sql0, Credential.class)
			        .setParameter("userName", userName)
			        .setParameter("domain", domain)
			        .setParameter("realm", realm)
			        .getSingleResult();

			final var sql1 = "DELETE Totpbackupcode t WHERE t.credential = :credential";
			entityManager.createQuery(sql1)
			        .setParameter("credential", credential)
			        .executeUpdate();

			entityManager.remove(credential.getUser());
			entityManager.remove(credential);
		} catch (final NoResultException e) {
			log.debug("Can't delete a non-found object {}@{}", userName, domain, e);
		}
	}

	@Override
	@Transactional
	public boolean deleteGroup(final String groupName) {
		final var sql = "DELETE Group g WHERE g.name = :groupName";
		return entityManager.createQuery(sql)
		        .setParameter("groupName", groupName)
		        .executeUpdate() == 1;
	}

}
