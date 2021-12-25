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

import static java.util.stream.Collectors.toUnmodifiableList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static tv.hd3g.authkit.mod.controller.ControllerLogin.TOKEN_FORMNAME_ENTER_TOTP;
import static tv.hd3g.authkit.mod.service.AuditReportService.RejectLoginCause.INVALID_PASSWORD;
import static tv.hd3g.authkit.mod.service.CookieService.AUTH_COOKIE_NAME;
import static tv.hd3g.authkit.mod.service.TOTPServiceImpl.base32;
import static tv.hd3g.authkit.mod.service.TOTPServiceImpl.makeCodeAtTime;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomIPv4;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomThing;
import static tv.hd3g.authkit.tool.DataGenerator.makeUUID;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserLogin;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserPassword;
import static tv.hd3g.authkit.tool.DataGenerator.thirtyDays;

import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import tv.hd3g.authkit.mod.dto.LoggedUserTagsTokenDto;
import tv.hd3g.authkit.mod.dto.LoginRequestContentDto;
import tv.hd3g.authkit.mod.dto.Password;
import tv.hd3g.authkit.mod.dto.ressource.UserPrivacyDto;
import tv.hd3g.authkit.mod.dto.validated.AddGroupOrRoleDto;
import tv.hd3g.authkit.mod.dto.validated.AddUserDto;
import tv.hd3g.authkit.mod.dto.validated.LoginFormDto;
import tv.hd3g.authkit.mod.dto.validated.RenameGroupOrRoleDto;
import tv.hd3g.authkit.mod.dto.validated.TOTPLogonCodeFormDto;
import tv.hd3g.authkit.mod.dto.validated.ValidationSetupTOTPDto;
import tv.hd3g.authkit.mod.exception.AuthKitException;
import tv.hd3g.authkit.mod.exception.BlockedUserException;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException;
import tv.hd3g.authkit.mod.exception.ResetWithSamePasswordException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.BadPasswordUserCantLoginException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.BlockedUserCantLoginException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.DisabledUserCantLoginException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.NoPasswordUserCantLoginException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.TOTPUserCantLoginException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.UnknownUserCantLoginException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.UserMustChangePasswordException;
import tv.hd3g.authkit.mod.repository.CredentialRepository;
import tv.hd3g.authkit.mod.repository.GroupRepository;
import tv.hd3g.authkit.mod.repository.RoleRepository;
import tv.hd3g.authkit.mod.repository.RoleRightContextRepository;
import tv.hd3g.authkit.mod.repository.RoleRightRepository;
import tv.hd3g.authkit.mod.repository.TotpbackupcodeRepository;
import tv.hd3g.authkit.mod.repository.UserDao;
import tv.hd3g.authkit.tool.DataGenerator;

@SpringBootTest
class AuthenticationServiceTest {

	@Autowired
	private AuthenticationService authenticationService;
	@Autowired
	private UserDao userDao;
	@Autowired
	private SecuredTokenService securedTokenService;
	@Autowired
	private CredentialRepository credentialRepository;
	@Autowired
	private GroupRepository groupRepository;
	@Autowired
	private RoleRepository roleRepository;
	@Autowired
	private RoleRightRepository roleRightRepository;
	@Autowired
	private RoleRightContextRepository roleRightContextRepository;
	@Autowired
	private TOTPService totpService;
	@Autowired
	private TotpbackupcodeRepository totpbackupcodeRepository;

	@Value("${authkit.longSessionDuration:24h}")
	private Duration longSessionDuration;
	@Value("${authkit.shortSessionDuration:10m}")
	private Duration shortSessionDuration;
	@Value("${authkit.maxLogonTrial:10}")
	private short maxLogonTrial;
	@Value("${authkit.totpTimeStepSeconds:30}")
	private int timeStepSeconds;
	@Value("${authkit.realm:default}")
	private String realm;

	@Value("${authkit.ldaptest.simpleUserName:}")
	private String ldapSimpleUserName;
	@Value("${authkit.ldaptest.simpleUserPassword:}")
	private String ldapSimpleUserPassword;
	@Value("${authkit.ldaptest.domain:}")
	private String domain;
	@Value("${authkit.ldaptest.simpleUserSecurGroup:}")
	private String simpleUserSecurGroup;
	@Value("${authkit.ldaptest.simpleUserDistrGroup:}")
	private String simpleUserDistrGroup;

	private AddUserDto addUser;
	private String userPassword;
	private String randomIp;
	@Mock
	private HttpServletRequest request;

	@BeforeEach
	void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		DataGenerator.setupMock(request);
		addUser = new AddUserDto();
		addUser.setUserLogin(makeUserLogin());
		userPassword = makeUserPassword();
		addUser.setUserPassword(new Password(userPassword));
		randomIp = makeRandomIPv4().getHostAddress();
	}

	@Nested
	class User {

		@Test
		void addUser() {
			final var uuid = authenticationService.addUser(addUser);
			assertNotNull(uuid);
			assertFalse(uuid.isEmpty());
			assertNull(getLastLogin(uuid));
		}

		@Test
		void addUserExists() {
			authenticationService.addUser(addUser);
			addUser.setUserPassword(new Password(userPassword));
			assertThrows(AuthKitException.class, () -> {
				authenticationService.addUser(addUser);
			});
		}

		@Test
		void removeUser() {
			final var uuid = authenticationService.addUser(addUser);
			authenticationService.removeUser(uuid);
			addUser.setUserPassword(new Password(userPassword));
			assertNotNull(authenticationService.addUser(addUser));
		}

		@Test
		void removeUserNotExists() {
			final var uuid = makeUUID();
			assertThrows(AuthKitException.class, () -> {
				authenticationService.removeUser(uuid);
			});
		}

		@Test
		void getRightsForUser_simpleRole() {
			final var uuid = authenticationService.addUser(addUser);
			final var list1 = authenticationService.getRightsForUser(uuid, randomIp);
			assertNotNull(list1);
			assertTrue(list1.isEmpty());

			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			authenticationService.addUserInGroup(uuid, g.getName());
			final var list2 = authenticationService.getRightsForUser(uuid, randomIp);
			assertTrue(list2.isEmpty());

			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			authenticationService.addGroupInRole(g.getName(), r.getName());
			final var list3 = authenticationService.getRightsForUser(uuid, randomIp);
			assertTrue(list3.isEmpty());

			final var rightName = makeUserLogin();
			authenticationService.addRightInRole(r.getName(), rightName);
			final var list4 = authenticationService.getRightsForUser(uuid, randomIp);
			assertEquals(1, list4.size());
			assertEquals(rightName, list4.get(0));
		}

		@Test
		void getRightsForUser_multipleGroups() {
			final var uuid = authenticationService.addUser(addUser);

			final var g1 = new AddGroupOrRoleDto();
			g1.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g1);
			authenticationService.addUserInGroup(uuid, g1.getName());

			final var r1 = new AddGroupOrRoleDto();
			r1.setName("test:" + makeUserLogin());
			authenticationService.addRole(r1);
			authenticationService.addGroupInRole(g1.getName(), r1.getName());

			final var rightName1 = makeUserLogin();
			authenticationService.addRightInRole(r1.getName(), rightName1);

			final var g2 = new AddGroupOrRoleDto();
			g2.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g2);
			authenticationService.addUserInGroup(uuid, g2.getName());

			final var r2 = new AddGroupOrRoleDto();
			r2.setName("test:" + makeUserLogin());
			authenticationService.addRole(r2);
			authenticationService.addGroupInRole(g2.getName(), r2.getName());

			final var rightName2 = makeUserLogin();
			authenticationService.addRightInRole(r2.getName(), rightName2);
			final var list = authenticationService.getRightsForUser(uuid, randomIp);
			assertEquals(2, list.size());
			assertTrue(list.contains(rightName1));
			assertTrue(list.contains(rightName2));
		}

		@Test
		void getRightsForUser_duplicateRole_inGroup() {
			final var uuid = authenticationService.addUser(addUser);

			final var g1 = new AddGroupOrRoleDto();
			g1.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g1);
			authenticationService.addUserInGroup(uuid, g1.getName());

			final var g2 = new AddGroupOrRoleDto();
			g2.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g2);
			authenticationService.addUserInGroup(uuid, g2.getName());

			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			authenticationService.addGroupInRole(g1.getName(), r.getName());
			authenticationService.addGroupInRole(g2.getName(), r.getName());

			final var rightName = makeUserLogin();
			authenticationService.addRightInRole(r.getName(), rightName);

			final var list = authenticationService.getRightsForUser(uuid, randomIp);
			assertEquals(1, list.size());
			assertTrue(list.contains(rightName));
		}

		@Test
		void getRightsForUser_duplicateRoleRight_inRole() {
			final var uuid = authenticationService.addUser(addUser);

			final var g1 = new AddGroupOrRoleDto();
			g1.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g1);
			authenticationService.addUserInGroup(uuid, g1.getName());

			final var r1 = new AddGroupOrRoleDto();
			r1.setName("test:" + makeUserLogin());
			authenticationService.addRole(r1);
			authenticationService.addGroupInRole(g1.getName(), r1.getName());

			final var g2 = new AddGroupOrRoleDto();
			g2.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g2);
			authenticationService.addUserInGroup(uuid, g2.getName());

			final var r2 = new AddGroupOrRoleDto();
			r2.setName("test:" + makeUserLogin());
			authenticationService.addRole(r2);
			authenticationService.addGroupInRole(g2.getName(), r2.getName());

			final var rightName = makeUserLogin();
			authenticationService.addRightInRole(r1.getName(), rightName);
			authenticationService.addRightInRole(r2.getName(), rightName);

			final var list = authenticationService.getRightsForUser(uuid, randomIp);
			assertEquals(1, list.size());
			assertTrue(list.contains(rightName));
		}

		@Test
		void getContextRightsForUser() {
			final var rightNameYep = makeUserLogin();
			final var rightNameNope = makeUserLogin();
			final var uuid = authenticationService.addUser(addUser);

			final var list1 = authenticationService.getContextRightsForUser(uuid, randomIp, rightNameYep);
			assertNotNull(list1);
			assertTrue(list1.isEmpty());

			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			authenticationService.addUserInGroup(uuid, g.getName());
			final var list2 = authenticationService.getContextRightsForUser(uuid, randomIp, rightNameYep);
			assertTrue(list2.isEmpty());

			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			authenticationService.addGroupInRole(g.getName(), r.getName());
			final var list3 = authenticationService.getContextRightsForUser(uuid, randomIp, rightNameYep);
			assertTrue(list3.isEmpty());

			authenticationService.addRightInRole(r.getName(), rightNameYep);
			authenticationService.addRightInRole(r.getName(), rightNameNope);
			final var list4 = authenticationService.getContextRightsForUser(uuid, randomIp, rightNameYep);
			assertTrue(list4.isEmpty());

			final var context1 = makeUserLogin();
			final var context2 = makeUserLogin();
			authenticationService.addContextInRight(r.getName(), rightNameYep, context1);
			authenticationService.addContextInRight(r.getName(), rightNameYep, context2);
			authenticationService.addContextInRight(r.getName(), rightNameNope, makeUserLogin());

			final var list5 = authenticationService.getContextRightsForUser(uuid, randomIp, rightNameYep);
			assertEquals(2, list5.size());
			assertTrue(list5.contains(context1));
			assertTrue(list5.contains(context2));
		}

		@Test
		void getRightsForUser_clientOnly() {
			final var uuid = authenticationService.addUser(addUser);
			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			authenticationService.addUserInGroup(uuid, g.getName());

			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			authenticationService.addGroupInRole(g.getName(), r.getName());
			final var rightName = makeUserLogin();
			authenticationService.addRightInRole(r.getName(), rightName);

			final var randomIp2 = makeRandomIPv4().getHostAddress();
			authenticationService.setRoleOnlyForClient(r.getName(), randomIp2);
			final var list1 = authenticationService.getRightsForUser(uuid, randomIp);
			assertEquals(0, list1.size());
			final var list2 = authenticationService.getRightsForUser(uuid, randomIp2);
			assertEquals(1, list2.size());
		}

		@Test
		void getContextRightsForUser_clientOnly() {
			final var rightName = makeUserLogin();
			final var uuid = authenticationService.addUser(addUser);

			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			authenticationService.addUserInGroup(uuid, g.getName());

			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			authenticationService.addGroupInRole(g.getName(), r.getName());
			authenticationService.addRightInRole(r.getName(), rightName);

			final var context1 = makeUserLogin();
			authenticationService.addContextInRight(r.getName(), rightName, context1);

			final var randomIp2 = makeRandomIPv4().getHostAddress();
			authenticationService.setRoleOnlyForClient(r.getName(), randomIp2);
			final var list1 = authenticationService.getContextRightsForUser(uuid, randomIp, rightName);
			assertEquals(0, list1.size());
			final var list2 = authenticationService.getContextRightsForUser(uuid, randomIp2, rightName);
			assertEquals(1, list2.size());
		}

	}

	@Test
	void checkPassword() throws Exception {
		final var uuid = authenticationService.addUser(addUser);
		final var credential = credentialRepository.getByUserUUID(uuid);

		final var resultOk = authenticationService.checkPassword(new Password(userPassword), credential);
		assertNotNull(resultOk);
		assertTrue(resultOk.isEmpty());

		final var resultErr = authenticationService.checkPassword(new Password(makeUserPassword()), credential);
		assertNotNull(resultErr);
		assertTrue(resultErr.isPresent());
		assertEquals(INVALID_PASSWORD, resultErr.get());
	}

	@Test
	void checkPassword_LDAP() throws Exception {
		if (ldapSimpleUserName == null || ldapSimpleUserName.isBlank()) {
			return;
		}
		/**
		 * Do a first auth for init LDAP User
		 */
		final var loginForm = new LoginFormDto();
		loginForm.setUserlogin(ldapSimpleUserName);
		loginForm.setUserpassword(new Password(ldapSimpleUserPassword));
		final var credential = credentialRepository.getFromRealmLogin(realm, ldapSimpleUserName);
		final var uuid = credential.getUser().getUuid();

		checkLoginRequestContent(authenticationService.userLoginRequest(request, loginForm), uuid);

		final var resultOk = authenticationService.checkPassword(new Password(ldapSimpleUserPassword), credential);
		assertNotNull(resultOk);
		assertTrue(resultOk.isEmpty());

		final var resultErr = authenticationService.checkPassword(new Password(makeUserPassword()), credential);
		assertNotNull(resultErr);
		assertTrue(resultErr.isPresent());
		assertEquals(INVALID_PASSWORD, resultErr.get());
	}

	private LoggedUserTagsTokenDto checkLoginRequestContent(final LoginRequestContentDto loginRequest,
	                                                        final String userUUID) {
		assertNotNull(loginRequest);
		final var token = loginRequest.getUserSessionToken();
		final var cookie = loginRequest.getUserSessionCookie();
		assertNotNull(token);
		assertNotNull(cookie);
		assertEquals(token, cookie.getValue());
		assertEquals(AUTH_COOKIE_NAME, cookie.getName());

		try {
			final var loggedUserTagsTokenDto = securedTokenService.loggedUserRightsExtractToken(token, false);
			assertEquals(userUUID, loggedUserTagsTokenDto.getUserUUID());
			return loggedUserTagsTokenDto;
		} catch (final NotAcceptableSecuredTokenException e) {
			throw new AssertionError("Can't extract token", e);
		}
	}

	@Test
	void setupTOTPWithChecks() throws GeneralSecurityException {
		final var addUser = new AddUserDto();
		addUser.setUserLogin(makeUserLogin());
		final var userPassword = makeUserPassword();
		addUser.setUserPassword(new Password(userPassword));
		final var uuid = authenticationService.addUser(addUser);
		final var secret = totpService.makeSecret();
		final var backupCodes = totpService.makeBackupCodes();

		final var setupDto = new ValidationSetupTOTPDto();
		final var checkCode = makeCodeAtTime(base32.decode(secret), System.currentTimeMillis(), timeStepSeconds);
		setupDto.setTwoauthcode(checkCode);
		final var controlToken = securedTokenService.setupTOTPGenerateToken(uuid, thirtyDays, secret, backupCodes);
		setupDto.setControlToken(controlToken);
		setupDto.setCurrentpassword(new Password(userPassword));

		authenticationService.setupTOTPWithChecks(setupDto, uuid);

		final var c = credentialRepository.getByUserUUID(uuid);
		assertNotNull(c);
		assertNotNull(c.getTotpkey());

		final var actualCodes = totpbackupcodeRepository.getByUserUUID(uuid);
		assertEquals(backupCodes.size(), actualCodes.size());
	}

	@Nested
	class UserLoginRequest {

		@Test
		void userLoginRequest() throws Exception {
			final var uuid = authenticationService.addUser(addUser);
			final var loginForm = new LoginFormDto();
			loginForm.setUserlogin(addUser.getUserLogin());
			loginForm.setUserpassword(new Password(userPassword));

			checkLoginRequestContent(authenticationService.userLoginRequest(request, loginForm), uuid);

			final var lastLogin = getLastLogin(uuid);
			assertNotNull(lastLogin);
			assertTrue(lastLogin.after(new Date(System.currentTimeMillis() - 10000)));
		}

		@Nested
		class LDAP {

			@BeforeEach
			void init() {
				if (ldapSimpleUserName == null || ldapSimpleUserName.isBlank()) {
					return;
				}
				userDao.deleteExternalUserCredential(ldapSimpleUserName, domain, realm);
				if (simpleUserSecurGroup != null && simpleUserSecurGroup.isEmpty() == false) {
					userDao.deleteGroup(simpleUserSecurGroup);
				}
				if (simpleUserDistrGroup != null && simpleUserDistrGroup.isEmpty() == false) {
					userDao.deleteGroup(simpleUserDistrGroup);
				}
			}

			@Test
			void userLoginRequest() throws Exception {
				if (ldapSimpleUserName == null || ldapSimpleUserName.isBlank()) {
					return;
				}
				final var loginForm = new LoginFormDto();
				loginForm.setUserlogin(ldapSimpleUserName);
				loginForm.setUserpassword(new Password(ldapSimpleUserPassword));

				final var c1 = credentialRepository.getFromRealmLogin(realm, ldapSimpleUserName);
				assertNotNull(c1);

				final var uuid = c1.getUser().getUuid();
				checkLoginRequestContent(authenticationService.userLoginRequest(request, loginForm), uuid);

				final var c2 = credentialRepository.getFromRealmLogin(realm, ldapSimpleUserName);
				assertNotNull(c2);

				final var lastLogin = c2.getLastlogin();
				assertNotNull(lastLogin);
				assertTrue(lastLogin.after(new Date(System.currentTimeMillis() - 10000)));
			}

			@Test
			void userLoginRequest_twice() throws Exception {
				if (ldapSimpleUserName == null || ldapSimpleUserName.isBlank()) {
					return;
				}
				final var c0 = credentialRepository.getFromRealmLogin(realm, ldapSimpleUserName);
				final var u0 = credentialRepository.getUUIDFromRealmLogin(realm, ldapSimpleUserName);
				assertNotNull(c0);
				assertNull(u0);
				final var uuid = c0.getUser().getUuid();

				final var loginForm = new LoginFormDto();
				loginForm.setUserlogin(ldapSimpleUserName);
				loginForm.setUserpassword(new Password(ldapSimpleUserPassword));

				checkLoginRequestContent(authenticationService.userLoginRequest(request, loginForm), uuid);

				final var c1 = credentialRepository.getFromRealmLogin(realm, ldapSimpleUserName);
				final var u1 = credentialRepository.getUUIDFromRealmLogin(realm, ldapSimpleUserName);

				loginForm.setUserpassword(new Password(ldapSimpleUserPassword));
				checkLoginRequestContent(authenticationService.userLoginRequest(request, loginForm), uuid);

				final var c2 = credentialRepository.getFromRealmLogin(realm, ldapSimpleUserName);
				final var u2 = credentialRepository.getUUIDFromRealmLogin(realm, ldapSimpleUserName);

				assertEquals(c1.getId(), c2.getId());
				assertEquals(u1, u2);
			}

			@Test
			void userLoginRequestInvalidPassword() throws Exception {
				if (ldapSimpleUserName == null || ldapSimpleUserName.isBlank()) {
					return;
				}
				final var loginForm = new LoginFormDto();
				loginForm.setUserlogin(ldapSimpleUserName);
				loginForm.setUserpassword(new Password(makeUserPassword()));

				assertThrows(UnknownUserCantLoginException.class, () -> {
					authenticationService.userLoginRequest(request, loginForm);
				});
			}

			@Test
			void userLoginRequestNoPassword() throws Exception {
				if (ldapSimpleUserName == null || ldapSimpleUserName.isBlank()) {
					return;
				}
				final var loginForm = new LoginFormDto();
				loginForm.setUserlogin(ldapSimpleUserName);

				assertThrows(UnknownUserCantLoginException.class, () -> {
					authenticationService.userLoginRequest(request, loginForm);
				});
			}

			@Test
			void userLoginRequest_TOTP() throws Exception {
				if (ldapSimpleUserName == null || ldapSimpleUserName.isBlank()) {
					return;
				}
				final var loginForm = new LoginFormDto();
				loginForm.setUserlogin(ldapSimpleUserName);
				loginForm.setUserpassword(new Password(ldapSimpleUserPassword));
				final var uuid = credentialRepository.getUUIDFromRealmLogin(realm, ldapSimpleUserName);

				checkLoginRequestContent(authenticationService.userLoginRequest(request, loginForm), uuid);

				final var secret = totpService.makeSecret();
				final var checkCode = makeCodeAtTime(base32.decode(secret), System.currentTimeMillis(),
				        timeStepSeconds);
				final var backupCodes = totpService.makeBackupCodes();
				totpService.setupTOTP(secret, backupCodes, uuid);

				final var tokenAuth = securedTokenService.userFormGenerateToken(TOKEN_FORMNAME_ENTER_TOTP, uuid,
				        thirtyDays);
				final var formTOTPDto = new TOTPLogonCodeFormDto();
				formTOTPDto.setCode(checkCode);
				formTOTPDto.setSecuretoken(tokenAuth);
				formTOTPDto.setShorttime(false);

				final var loginRequest = authenticationService.userLoginRequest(request, formTOTPDto);
				assertNotNull(loginRequest);
				assertFalse(loginRequest.getUserSessionToken().isEmpty());

				final var lastLogin = getLastLogin(uuid);
				assertNotNull(lastLogin);
				assertTrue(lastLogin.after(new Date(System.currentTimeMillis() - 10000)));

				/**
				 * Try now with "classic" (no TOTP) method
				 */
				loginForm.setUserpassword(new Password(ldapSimpleUserPassword));
				assertThrows(TOTPUserCantLoginException.class, () -> {
					authenticationService.userLoginRequest(request, loginForm);
				});
			}

		}

		@Test
		void userLoginRequest_maxLogonTrial_UnderLimit() throws Exception {
			final var uuid = authenticationService.addUser(addUser);
			final var loginFormFail = new LoginFormDto();
			loginFormFail.setUserlogin(addUser.getUserLogin());

			for (var pos = 0; pos < maxLogonTrial - 1; pos++) {
				loginFormFail.setUserpassword(new Password(makeUserPassword()));
				assertThrows(BadPasswordUserCantLoginException.class, () -> {
					authenticationService.userLoginRequest(request, loginFormFail);
				});
			}

			final var loginFormOk = new LoginFormDto();
			loginFormOk.setUserlogin(addUser.getUserLogin());
			loginFormOk.setUserpassword(new Password(userPassword));
			checkLoginRequestContent(authenticationService.userLoginRequest(request, loginFormOk), uuid);
		}

		@Test
		void userLoginRequest_maxLogonTrial_OverLimit() throws Exception {
			authenticationService.addUser(addUser);
			final var loginFormFail = new LoginFormDto();
			loginFormFail.setUserlogin(addUser.getUserLogin());

			for (var pos = 0; pos < maxLogonTrial; pos++) {
				loginFormFail.setUserpassword(new Password(makeUserPassword()));
				assertThrows(BadPasswordUserCantLoginException.class, () -> {
					authenticationService.userLoginRequest(request, loginFormFail);
				});
			}

			loginFormFail.setUserpassword(new Password(makeUserPassword()));
			assertThrows(BlockedUserCantLoginException.class, () -> {
				authenticationService.userLoginRequest(request, loginFormFail);
			});

			final var loginFormOk = new LoginFormDto();
			loginFormOk.setUserlogin(addUser.getUserLogin());
			loginFormOk.setUserpassword(new Password(userPassword));
			assertThrows(BlockedUserCantLoginException.class, () -> {
				authenticationService.userLoginRequest(request, loginFormOk);
			});
		}

		@Test
		void userLoginRequestLongDuration() throws Exception {
			final var uuid = authenticationService.addUser(addUser);
			final var loginForm = new LoginFormDto();
			loginForm.setUserlogin(addUser.getUserLogin());
			loginForm.setUserpassword(new Password(userPassword));
			final var loginRequest = authenticationService.userLoginRequest(request, loginForm);
			final var loggedUser = checkLoginRequestContent(loginRequest, uuid);

			/**
			 * Test if login still ok after short duration time
			 */
			assertTrue(loggedUser.getTimeout().after(
			        new Date(System.currentTimeMillis() + shortSessionDuration.getSeconds() * 1000)));
		}

		@Test
		void userLoginRequestShortDuration() throws Exception {
			final var uuid = authenticationService.addUser(addUser);
			final var loginForm = new LoginFormDto();
			loginForm.setUserlogin(addUser.getUserLogin());
			loginForm.setUserpassword(new Password(userPassword));
			loginForm.setShorttime(true);
			final var loggedUser = checkLoginRequestContent(authenticationService
			        .userLoginRequest(request, loginForm), uuid);

			/**
			 * Test if not logged before long duration time
			 */
			assertTrue(loggedUser.getTimeout().before(
			        new Date(System.currentTimeMillis() + longSessionDuration.getSeconds() * 1000)));
		}

		@Test
		void userLoginRequestInvalidUser() throws Exception {
			final var loginForm = new LoginFormDto();
			loginForm.setUserlogin(addUser.getUserLogin());
			loginForm.setUserpassword(new Password(userPassword));

			assertThrows(UnknownUserCantLoginException.class, () -> {
				authenticationService.userLoginRequest(request, loginForm);
			});
		}

		@Test
		void userLoginRequestInvalidPassword() throws Exception {
			final var uuid = authenticationService.addUser(addUser);
			final var loginForm = new LoginFormDto();
			loginForm.setUserlogin(addUser.getUserLogin());
			loginForm.setUserpassword(new Password(makeUserPassword()));

			assertThrows(BadPasswordUserCantLoginException.class, () -> {
				authenticationService.userLoginRequest(request, loginForm);
			});
			assertNull(getLastLogin(uuid));
		}

		@Test
		void userLoginRequestNoPassword() throws Exception {
			final var uuid = authenticationService.addUser(addUser);
			final var loginForm = new LoginFormDto();
			loginForm.setUserlogin(addUser.getUserLogin());

			assertThrows(NoPasswordUserCantLoginException.class, () -> {
				authenticationService.userLoginRequest(request, loginForm);
			});
			assertNull(getLastLogin(uuid));
		}

		@Test
		void userLoginRequestUserMustChangePassword() throws Exception {
			final var uuid = authenticationService.addUser(addUser);
			authenticationService.setUserMustChangePassword(uuid);
			final var loginForm = new LoginFormDto();
			loginForm.setUserlogin(addUser.getUserLogin());
			loginForm.setUserpassword(new Password(userPassword));

			assertThrows(UserMustChangePasswordException.class, () -> {
				authenticationService.userLoginRequest(request, loginForm);
			});
			assertNull(getLastLogin(uuid));
		}

		@Test
		void userLoginRequestDisabledUser() throws Exception {
			final var uuid = authenticationService.addUser(addUser);
			authenticationService.disableUser(uuid);
			final var loginForm = new LoginFormDto();
			loginForm.setUserlogin(addUser.getUserLogin());
			loginForm.setUserpassword(new Password(userPassword));

			assertThrows(DisabledUserCantLoginException.class, () -> {
				authenticationService.userLoginRequest(request, loginForm);
			});
			assertNull(getLastLogin(uuid));
		}

		void userLoginRequestEnabledUser() throws Exception {
			final var uuid = authenticationService.addUser(addUser);
			authenticationService.disableUser(uuid);
			authenticationService.enableUser(uuid);
			final var loginForm = new LoginFormDto();
			loginForm.setUserlogin(addUser.getUserLogin());
			loginForm.setUserpassword(new Password(userPassword));
			checkLoginRequestContent(authenticationService.userLoginRequest(request, loginForm), uuid);

			final var lastLogin = getLastLogin(uuid);
			assertNotNull(lastLogin);
			assertTrue(lastLogin.after(new Date(System.currentTimeMillis() - 10000)));
		}

		@Test
		void userLoginRequest_TOTP() throws Exception {
			final var uuid = authenticationService.addUser(addUser);
			final var secret = totpService.makeSecret();
			final var checkCode = makeCodeAtTime(base32.decode(secret), System.currentTimeMillis(), timeStepSeconds);
			final var backupCodes = totpService.makeBackupCodes();
			totpService.setupTOTP(secret, backupCodes, uuid);

			final var tokenAuth = securedTokenService.userFormGenerateToken(TOKEN_FORMNAME_ENTER_TOTP, uuid,
			        thirtyDays);
			final var formTOTPDto = new TOTPLogonCodeFormDto();
			formTOTPDto.setCode(checkCode);
			formTOTPDto.setSecuretoken(tokenAuth);
			formTOTPDto.setShorttime(false);

			final var loginRequest = authenticationService.userLoginRequest(request, formTOTPDto);
			assertNotNull(loginRequest);
			assertFalse(loginRequest.getUserSessionToken().isEmpty());

			final var lastLogin = getLastLogin(uuid);
			assertNotNull(lastLogin);
			assertTrue(lastLogin.after(new Date(System.currentTimeMillis() - 10000)));

			/**
			 * Try now with "classic" (no TOTP) method
			 */
			final var loginForm = new LoginFormDto();
			loginForm.setUserlogin(addUser.getUserLogin());
			loginForm.setUserpassword(new Password(userPassword));
			assertThrows(TOTPUserCantLoginException.class, () -> {
				authenticationService.userLoginRequest(request, loginForm);
			});
		}

		@Test
		void userLoginRequestRoleWithIPRestriction_differentAddr() throws Exception {
			final var uuid = authenticationService.addUser(addUser);

			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			authenticationService.addUserInGroup(uuid, g.getName());
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			authenticationService.addGroupInRole(g.getName(), r.getName());
			final var rightName = makeUserLogin();
			authenticationService.addRightInRole(r.getName(), rightName);
			final var addr = makeRandomIPv4().getHostAddress();
			authenticationService.setRoleOnlyForClient(r.getName(), addr);

			final var loginForm = new LoginFormDto();
			loginForm.setUserlogin(addUser.getUserLogin());
			loginForm.setUserpassword(new Password(userPassword));

			final var loggedDto = checkLoginRequestContent(authenticationService
			        .userLoginRequest(request, loginForm), uuid);
			assertNull(loggedDto.getOnlyForHost());
			assertTrue(loggedDto.getTags().isEmpty());
		}

		@Test
		void userLoginRequestRoleWithIPRestriction_sameAddr() throws Exception {
			final var uuid = authenticationService.addUser(addUser);

			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			authenticationService.addUserInGroup(uuid, g.getName());
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			authenticationService.addGroupInRole(g.getName(), r.getName());
			final var rightName = makeUserLogin();
			authenticationService.addRightInRole(r.getName(), rightName);
			final var addr = request.getRemoteAddr();
			authenticationService.setRoleOnlyForClient(r.getName(), addr);

			final var loginForm = new LoginFormDto();
			loginForm.setUserlogin(addUser.getUserLogin());
			loginForm.setUserpassword(new Password(userPassword));

			final var loggedDto = checkLoginRequestContent(authenticationService
			        .userLoginRequest(request, loginForm), uuid);
			assertEquals(addr, loggedDto.getOnlyForHost());
			assertTrue(loggedDto.getTags().contains(rightName));
		}
	}

	@Test
	void resetUserLogonTrials() throws Exception {
		final var uuid = authenticationService.addUser(addUser);
		final var c = credentialRepository.getByUserUUID(uuid);
		c.setLogontrial(100);
		credentialRepository.save(c);
		authenticationService.resetUserLogonTrials(uuid);
		credentialRepository.flush();
		final var c2 = credentialRepository.getByUserUUID(uuid);
		assertEquals(0, c2.getLogontrial());
	}

	@Nested
	class IsUserEnabledAndNonBlocked {

		@Test
		void isUserEnabledAndNonBlocked_ok() throws Exception {
			final var uuid = authenticationService.addUser(addUser);
			assertTrue(authenticationService.isUserEnabledAndNonBlocked(uuid));
		}

		@Test
		void isUserEnabledAndNonBlocked_blocked() throws Exception {
			final var uuid = authenticationService.addUser(addUser);
			final var c = credentialRepository.getByUserUUID(uuid);
			c.setLogontrial(100);
			credentialRepository.save(c);
			assertFalse(authenticationService.isUserEnabledAndNonBlocked(uuid));
		}

		@Test
		void isUserEnabledAndNonBlocked_disabled() throws Exception {
			final var uuid = authenticationService.addUser(addUser);
			final var c = credentialRepository.getByUserUUID(uuid);
			c.setEnabled(false);
			credentialRepository.save(c);
			assertFalse(authenticationService.isUserEnabledAndNonBlocked(uuid));
		}

		@Test
		void isUserEnabledAndNonBlocked_mustchangepassword() throws Exception {
			final var uuid = authenticationService.addUser(addUser);
			final var c = credentialRepository.getByUserUUID(uuid);
			c.setMustchangepassword(true);
			credentialRepository.save(c);
			assertFalse(authenticationService.isUserEnabledAndNonBlocked(uuid));
		}

		@Test
		void isUserEnabledAndNonBlocked_deleted() throws Exception {
			assertFalse(authenticationService.isUserEnabledAndNonBlocked(makeUUID()));
		}
	}

	@Nested
	class ChangeUserPassword {

		@Test
		void changeUserPassword() throws Exception {
			final var uuid = authenticationService.addUser(addUser);
			final var newPassword = makeUserPassword();
			authenticationService.changeUserPassword(uuid, new Password(newPassword));

			final var loginForm = new LoginFormDto();
			loginForm.setUserlogin(addUser.getUserLogin());
			loginForm.setUserpassword(new Password(newPassword));

			checkLoginRequestContent(authenticationService.userLoginRequest(request, loginForm), uuid);

			final var lastLogin = getLastLogin(uuid);
			assertNotNull(lastLogin);
			assertTrue(lastLogin.after(new Date(System.currentTimeMillis() - 10000)));
		}

		@Test
		void changeUserPassword_SamePassword() throws Exception {
			final var uuid = authenticationService.addUser(addUser);
			assertThrows(ResetWithSamePasswordException.class, () -> {
				authenticationService.changeUserPassword(uuid, new Password(userPassword));
			});
		}

		@Test
		void changeUserPassword_BlockedUser() throws Exception {
			final var uuid = authenticationService.addUser(addUser);
			final var loginFormFail = new LoginFormDto();
			loginFormFail.setUserlogin(addUser.getUserLogin());

			for (var pos = 0; pos < maxLogonTrial; pos++) {
				loginFormFail.setUserpassword(new Password(makeUserPassword()));
				assertThrows(BadPasswordUserCantLoginException.class, () -> {
					authenticationService.userLoginRequest(request, loginFormFail);
				});
			}

			assertThrows(BlockedUserException.class, () -> {
				authenticationService.changeUserPassword(uuid, new Password(makeUserPassword()));
			});
		}
	}

	private Date getLastLogin(final String uuid) {
		return userDao.getUserByUUID(UUID.fromString(uuid)).get().getLastlogin();
	}

	@Nested
	class Group {

		@Test
		void addGroup() {
			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			g.setDescription(makeRandomThing());
			authenticationService.addGroup(g);
			final var gg = groupRepository.getByName(g.getName());
			assertNotNull(gg);
			assertEquals(g.getName(), gg.getName());
			assertEquals(g.getDescription(), gg.getDescription());
		}

		@Test
		void renameGroup() {
			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			final var gg = groupRepository.getByName(g.getName());
			final var id = gg.getId();

			final var renameGroup = new RenameGroupOrRoleDto();
			renameGroup.setName(g.getName());
			renameGroup.setNewname("test:" + makeUserLogin());
			authenticationService.renameGroup(renameGroup);

			final var gg2 = groupRepository.getByName(renameGroup.getNewname());
			assertNotNull(gg2);
			assertEquals(renameGroup.getNewname(), gg2.getName());
			assertEquals(id, gg2.getId());
		}

		@Test
		void setGroupDescription() {
			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			g.setDescription(makeRandomThing());
			authenticationService.addGroup(g);
			final var gg = groupRepository.getByName(g.getName());
			final var id = gg.getId();

			final var changeGroup = new AddGroupOrRoleDto();
			changeGroup.setName(g.getName());
			changeGroup.setDescription(makeRandomThing());
			authenticationService.setGroupDescription(changeGroup);

			final var gg2 = groupRepository.getByName(g.getName());
			assertNotNull(gg2);
			assertEquals(changeGroup.getDescription(), gg2.getDescription());
			assertEquals(id, gg2.getId());
		}

		@Test
		void addUserInGroup() {
			final var uuid = authenticationService.addUser(addUser);
			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			authenticationService.addUserInGroup(uuid, g.getName());

			final var list = groupRepository.getByUserUUID(uuid);
			assertEquals(1, list.size());
			assertEquals(g.getName(), list.get(0).getName());
		}

		@Test
		void removeUserInGroup() {
			final var uuid = authenticationService.addUser(addUser);
			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			authenticationService.addUserInGroup(uuid, g.getName());
			authenticationService.removeUserInGroup(uuid, g.getName());

			final var list = groupRepository.getByUserUUID(uuid);
			assertTrue(list.isEmpty());
		}

		@Test
		void removeGroup() {
			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			authenticationService.removeGroup(g.getName());
			assertNull(groupRepository.getByName(g.getName()));
		}

		@Test
		void listAllGroups() {
			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);

			final var list = authenticationService.listAllGroups();
			assertNotNull(list);
			final var groups = list.stream().filter(gg -> gg.getName().equals(g.getName()))
			        .collect(Collectors.toUnmodifiableList());
			assertEquals(1, groups.size());
		}

		@Test
		void listGroupsForUser() {
			final var uuid = authenticationService.addUser(addUser);
			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			authenticationService.addUserInGroup(uuid, g.getName());

			final var list = authenticationService.listGroupsForUser(uuid);
			assertNotNull(list);
			assertEquals(1, list.size());
			assertEquals(g.getName(), list.get(0).getName());
		}
	}

	@Nested
	class Role {

		@Test
		void addRole() {
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			r.setDescription(makeRandomThing());
			authenticationService.addRole(r);
			final var rr = roleRepository.getByName(r.getName());
			assertNotNull(rr);
			assertEquals(r.getName(), rr.getName());
			assertEquals(r.getDescription(), rr.getDescription());
		}

		@Test
		void renameRole() {
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			final var rr = roleRepository.getByName(r.getName());
			final var id = rr.getId();

			final var renameRole = new RenameGroupOrRoleDto();
			renameRole.setName(r.getName());
			renameRole.setNewname("test:" + makeUserLogin());
			authenticationService.renameRole(renameRole);

			final var rr2 = roleRepository.getByName(renameRole.getNewname());
			assertNotNull(rr2);
			assertEquals(renameRole.getNewname(), rr2.getName());
			assertEquals(id, rr2.getId());
		}

		@Test
		void setRoleDescription() {
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			r.setDescription(makeRandomThing());
			authenticationService.addRole(r);
			final var rr = roleRepository.getByName(r.getName());
			final var id = rr.getId();

			final var changeRole = new AddGroupOrRoleDto();
			changeRole.setName(r.getName());
			changeRole.setDescription(makeRandomThing());
			authenticationService.setRoleDescription(changeRole);

			final var rr2 = roleRepository.getByName(r.getName());
			assertNotNull(rr2);
			assertEquals(changeRole.getDescription(), rr2.getDescription());
			assertEquals(id, rr2.getId());
		}

		@Test
		void setRoleOnlyForClients_ipv4() throws UnknownHostException {
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			final var addr = DataGenerator.makeRandomIPv4().getHostAddress();
			authenticationService.setRoleOnlyForClient(r.getName(), addr);

			final var rr2 = roleRepository.getByName(r.getName());
			assertEquals(addr, rr2.getOnlyforclient());
		}

		@Test
		void setRoleOnlyForClients_ipv6() throws UnknownHostException {
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			final var addr = DataGenerator.makeRandomIPv6().getHostAddress();
			authenticationService.setRoleOnlyForClient(r.getName(), addr);

			final var rr2 = roleRepository.getByName(r.getName());
			assertEquals(addr, rr2.getOnlyforclient());
		}

		@Test
		void setRoleOnlyForClients_invalidIp() throws UnknownHostException {
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);

			final var name = r.getName();
			final var thing = makeRandomThing();
			Assertions.assertThrows(IllegalArgumentException.class,
			        () -> authenticationService.setRoleOnlyForClient(name, thing));
		}

		@Test
		void addGroupInRole() {
			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);

			authenticationService.addGroupInRole(g.getName(), r.getName());

			final var list = roleRepository.getByGroupName(g.getName());
			assertEquals(1, list.size());
			assertEquals(r.getName(), list.get(0).getName());
		}

		@Test
		void removeGroupInRole() {
			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);

			authenticationService.addGroupInRole(g.getName(), r.getName());
			authenticationService.removeGroupInRole(g.getName(), r.getName());

			final var list = roleRepository.getByGroupName(g.getName());
			assertEquals(0, list.size());
		}

		@Test
		void removeRole() {
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			authenticationService.removeRole(r.getName());
			assertNull(roleRepository.getByName(r.getName()));
		}

		@Test
		void listAllRoles() {
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);

			final var list = authenticationService.listAllRoles();
			assertNotNull(list);
			final var roles = list.stream().filter(rr -> rr.getName().equals(r.getName()))
			        .collect(Collectors.toUnmodifiableList());
			assertEquals(1, roles.size());
		}

		@Test
		void listRolesForGroup() {
			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);

			authenticationService.addGroupInRole(g.getName(), r.getName());

			final var list = authenticationService.listRolesForGroup(g.getName());
			assertNotNull(list);
			assertEquals(1, list.size());
			assertEquals(r.getName(), list.get(0).getName());
		}
	}

	@Nested
	class Right {

		@Test
		void addRightInRole() {
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			final var rightName = makeUserLogin();
			authenticationService.addRightInRole(r.getName(), rightName);
			final var rr = roleRightRepository.getRoleRight(r.getName(), rightName);
			assertNotNull(rr);
			assertEquals(rightName, rr.getName());
		}

		@Test
		void removeRightInRole() {
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			final var rightName = makeUserLogin();
			authenticationService.addRightInRole(r.getName(), rightName);
			authenticationService.removeRightInRole(r.getName(), rightName);
			final var rr = roleRightRepository.getRoleRight(r.getName(), rightName);
			assertNull(rr);
		}

		@Test
		void listAllRights() {
			final var list = authenticationService.getAllRights();
			assertNotNull(list);
			assertFalse(list.isEmpty());
		}

		@Test
		void listRightsForRole() {
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			final var rightName = makeUserLogin();
			authenticationService.addRightInRole(r.getName(), rightName);

			final var list = authenticationService.listRightsForRole(r.getName());
			assertNotNull(list);
			assertEquals(1, list.size());
			assertEquals(rightName, list.get(0));
		}

		@Test
		void addContextInRight() {
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			final var rightName = makeUserLogin();
			authenticationService.addRightInRole(r.getName(), rightName);
			final var context = makeUserLogin();
			authenticationService.addContextInRight(r.getName(), rightName, context);

			final var list = roleRightContextRepository.listContextsForRightRole(r.getName(), rightName);
			assertTrue(list.contains(context));
		}

		@Test
		void removeContextInRight() {
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			final var rightName = makeUserLogin();
			authenticationService.addRightInRole(r.getName(), rightName);
			final var context = makeUserLogin();
			authenticationService.addContextInRight(r.getName(), rightName, context);
			authenticationService.removeContextInRight(r.getName(), rightName, context);

			final var list = roleRightContextRepository.listContextsForRightRole(r.getName(), rightName);
			assertTrue(list.isEmpty());
		}

		@Test
		void listContextsForRight() {
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			final var rightName = makeUserLogin();
			authenticationService.addRightInRole(r.getName(), rightName);
			final var context = makeUserLogin();
			authenticationService.addContextInRight(r.getName(), rightName, context);

			final var list = authenticationService.listContextsForRight(r.getName(), rightName);
			assertTrue(list.contains(context));
		}

		@Test
		void listLinkedUsersForGroup() {
			final var uuid = authenticationService.addUser(addUser);
			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			authenticationService.addUserInGroup(uuid, g.getName());

			final var list = authenticationService.listLinkedUsersForGroup(g.getName());
			assertNotNull(list);
			assertEquals(1, list.size());
			assertEquals(uuid, list.get(0).getUuid());
		}

		@Test
		void listLinkedGroupsForRole() {
			final var g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			final var r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			authenticationService.addGroupInRole(g.getName(), r.getName());

			final var list = authenticationService.listLinkedGroupsForRole(r.getName());
			assertNotNull(list);
			assertEquals(1, list.size());
			assertEquals(g.getName(), list.get(0).getName());
		}
	}

	@Test
	void getSetUserPrivacyList() {
		final var empty = authenticationService.getUserPrivacyList(List.of(makeUUID()));
		assertNotNull(empty);
		assertTrue(empty.isEmpty());

		final var uuidList = IntStream.range(0, 10).mapToObj(i -> makeUUID()).collect(toUnmodifiableList());

		final var expectedItems = uuidList.stream().collect(Collectors.toUnmodifiableMap(u -> u, u -> {
			final var userPrivacyDto = new UserPrivacyDto();
			userPrivacyDto.setAddress(makeUserLogin());
			userPrivacyDto.setCompany(makeUserLogin());
			userPrivacyDto.setCountry(Locale.getDefault().getISO3Country());
			userPrivacyDto.setLang(Locale.getDefault().getISO3Language());
			userPrivacyDto.setEmail(makeUserLogin());
			userPrivacyDto.setName(makeRandomThing());
			userPrivacyDto.setPhone(makeUserLogin());
			userPrivacyDto.setPostalcode(String.valueOf(DataGenerator.random.nextInt(0, 1_000_000)));
			return userPrivacyDto;
		}));

		/**
		 * Check push
		 */
		uuidList.forEach(uuid -> authenticationService.setUserPrivacy(uuid, expectedItems.get(uuid)));

		/**
		 * Check get
		 */
		final var list1 = authenticationService.getUserPrivacyList(uuidList);
		assertNotNull(list1);
		assertEquals(uuidList.size(), list1.size());

		for (final var item : list1) {
			final var expected = expectedItems.get(item.getUserUUID());
			assertEquals(expected.getAddress(), item.getAddress());
			assertEquals(expected.getCompany(), item.getCompany());
			assertEquals(expected.getCountry(), item.getCountry());
			assertEquals(expected.getEmail(), item.getEmail());
			assertEquals(expected.getLang(), item.getLang());
			assertEquals(expected.getName(), item.getName());
			assertEquals(expected.getPhone(), item.getPhone());
			assertEquals(expected.getPostalcode(), item.getPostalcode());
		}

		/**
		 * Check update
		 */
		uuidList.forEach(uuid -> {
			final var userPrivacyDto = expectedItems.get(uuid);
			userPrivacyDto.setAddress(makeUserLogin());
			userPrivacyDto.setCompany(makeUserLogin());
			userPrivacyDto.setName(makeRandomThing());
			authenticationService.setUserPrivacy(uuid, userPrivacyDto);
		});

		final var list2 = authenticationService.getUserPrivacyList(uuidList);
		assertNotNull(list2);
		assertEquals(uuidList.size(), list2.size());

		for (final var item : list2) {
			final var expected = expectedItems.get(item.getUserUUID());
			assertEquals(expected.getAddress(), item.getAddress());
			assertEquals(expected.getCompany(), item.getCompany());
			assertEquals(expected.getCountry(), item.getCountry());
			assertEquals(expected.getEmail(), item.getEmail());
			assertEquals(expected.getLang(), item.getLang());
			assertEquals(expected.getName(), item.getName());
			assertEquals(expected.getPhone(), item.getPhone());
			assertEquals(expected.getPostalcode(), item.getPostalcode());
		}
	}
}
