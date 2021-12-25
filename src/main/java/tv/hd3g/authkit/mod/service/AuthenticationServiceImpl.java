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

import static java.util.stream.Collectors.toUnmodifiableSet;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static tv.hd3g.authkit.mod.controller.ControllerLogin.TOKEN_FORMNAME_ENTER_TOTP;
import static tv.hd3g.authkit.mod.service.AuditReportService.RejectLoginCause.DISABLED_LOGIN;
import static tv.hd3g.authkit.mod.service.AuditReportService.RejectLoginCause.EMPTY_PASSWORD;
import static tv.hd3g.authkit.mod.service.AuditReportService.RejectLoginCause.INVALID_PASSWORD;
import static tv.hd3g.authkit.mod.service.AuditReportService.RejectLoginCause.MISSING_PASSWORD;
import static tv.hd3g.authkit.mod.service.AuditReportService.RejectLoginCause.USER_NOT_FOUND;
import static tv.hd3g.authkit.mod.service.AuditReportServiceImpl.getOriginalRemoteAddr;
import static tv.hd3g.authkit.mod.service.ValidPasswordPolicyService.PasswordValidationLevel.DEFAULT;
import static tv.hd3g.authkit.utility.LogSanitizer.sanitize;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import tv.hd3g.authkit.mod.component.AuthKitEndpointsListener;
import tv.hd3g.authkit.mod.dto.LoginRequestContentDto;
import tv.hd3g.authkit.mod.dto.Password;
import tv.hd3g.authkit.mod.dto.SetupTOTPTokenDto;
import tv.hd3g.authkit.mod.dto.ressource.GroupOrRoleDto;
import tv.hd3g.authkit.mod.dto.ressource.UserDto;
import tv.hd3g.authkit.mod.dto.ressource.UserPrivacyDto;
import tv.hd3g.authkit.mod.dto.validated.AddGroupOrRoleDto;
import tv.hd3g.authkit.mod.dto.validated.AddUserDto;
import tv.hd3g.authkit.mod.dto.validated.LoginFormDto;
import tv.hd3g.authkit.mod.dto.validated.RenameGroupOrRoleDto;
import tv.hd3g.authkit.mod.dto.validated.TOTPLogonCodeFormDto;
import tv.hd3g.authkit.mod.dto.validated.ValidationSetupTOTPDto;
import tv.hd3g.authkit.mod.dto.validated.ValidationTOTPDto;
import tv.hd3g.authkit.mod.entity.Credential;
import tv.hd3g.authkit.mod.entity.Group;
import tv.hd3g.authkit.mod.entity.Role;
import tv.hd3g.authkit.mod.entity.RoleRight;
import tv.hd3g.authkit.mod.entity.RoleRightContext;
import tv.hd3g.authkit.mod.entity.User;
import tv.hd3g.authkit.mod.entity.Userprivacy;
import tv.hd3g.authkit.mod.exception.AuthKitException;
import tv.hd3g.authkit.mod.exception.BlockedUserException;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException;
import tv.hd3g.authkit.mod.exception.PasswordComplexityException;
import tv.hd3g.authkit.mod.exception.ResetWithSamePasswordException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.BadPasswordUserCantLoginException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.BadTOTPCodeCantLoginException;
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
import tv.hd3g.authkit.mod.repository.UserDao;
import tv.hd3g.authkit.mod.repository.UserPrivacyRepository;
import tv.hd3g.authkit.mod.repository.UserRepository;
import tv.hd3g.authkit.mod.service.AuditReportService.RejectLoginCause;

@Service
@Transactional(readOnly = false)
public class AuthenticationServiceImpl implements AuthenticationService {
	private static final Argon2 ARGON2 = Argon2Factory.create();
	private static final String MSG_CANT_FOUND_CREDENTIAL_FOR_USER = "Can't found Credential for user ";

	private static Logger log = LogManager.getLogger();

	@Autowired
	private SecuredTokenService tokenService;
	@Autowired
	private CredentialRepository credentialRepository;
	@Autowired
	private AuditReportService auditReportService;
	@Autowired
	private CipherService cipherService;
	@Autowired
	private TOTPService totpService;
	@Autowired
	private AuthKitEndpointsListener authKitEndpointsListener;
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private GroupRepository groupRepository;
	@Autowired
	private RoleRepository roleRepository;
	@Autowired
	private RoleRightRepository roleRightRepository;
	@Autowired
	private RoleRightContextRepository roleRightContextRepository;
	@Autowired
	private UserDao userDao;
	@Autowired
	private UserPrivacyRepository userPrivacyRepository;
	@Autowired
	private ValidPasswordPolicyService validPasswordPolicy;
	@Autowired
	private ExternalAuthClientService externalAuthClientService;
	@Autowired
	private CookieService cookieService;

	@Value("${authkit.realm:default}")
	private String realm;
	@Value("${authkit.longSessionDuration:24h}")
	private Duration longSessionDuration;
	@Value("${authkit.shortSessionDuration:10m}")
	private Duration shortSessionDuration;
	@Value("${authkit.maxLogonTrial:10}")
	private short maxLogonTrial;

	/**
	 * Number of iterations
	 */
	@Value("${authkit.argon2.iterations:10}")
	private int iterations;
	/**
	 * Sets memory usage to x kibibytes
	 */
	@Value("${authkit.argon2.memory:2048}")
	private int memory;
	/**
	 * Number of threads and compute lanes
	 */
	@Value("${authkit.argon2.parallelism:2}")
	private int parallelism;

	private User getUserByUUID(final String userUUID) {
		return Optional.ofNullable(userRepository.getByUUID(userUUID)).orElseThrow(
		        () -> new AuthKitException("Can't found User " + userUUID));
	}

	private Group getGroupByName(final String name) {
		return Optional.ofNullable(groupRepository.getByName(name)).orElseThrow(
		        () -> new AuthKitException("Can't found group \"" + name + "\""));
	}

	private Role getRoleByName(final String name) {
		return Optional.ofNullable(roleRepository.getByName(name)).orElseThrow(
		        () -> new AuthKitException("Can't found role \"" + name + "\""));
	}

	private RoleRight getRoleRight(final String roleName, final String rightName) {
		return Optional.ofNullable(roleRightRepository.getRoleRight(roleName, rightName)).orElseThrow(
		        () -> new AuthKitException("Can't found role right \"" + roleName + ":" + rightName + "\""));
	}

	@Override
	public Optional<RejectLoginCause> checkPassword(final Password userEnterPassword, final Credential credential) {
		if (userEnterPassword == null) {
			return Optional.ofNullable(MISSING_PASSWORD);
		} else if (userEnterPassword.length() == 0) {
			return Optional.ofNullable(EMPTY_PASSWORD);
		} else if (credential.getLdapdomain() != null) {
			try {
				externalAuthClientService.logonUser(credential.getLogin(), userEnterPassword, credential
				        .getLdapdomain());
			} catch (final UserCantLoginException e) {
				return Optional.ofNullable(INVALID_PASSWORD);
			}
		} else {
			final var passwordHash = cipherService.unCipherToString(credential.getPasswordhash());
			if (userEnterPassword.verify(ARGON2, passwordHash) == false) {
				return Optional.ofNullable(INVALID_PASSWORD);
			}
		}
		return Optional.empty();
	}

	private void checkLoginUserIsEnabled(final HttpServletRequest request,
	                                     final Credential credential,
	                                     final String what) throws DisabledUserCantLoginException {
		if (credential.isEnabled() == false) {
			auditReportService.onRejectLogin(request, DISABLED_LOGIN, realm, what);
			throw new DisabledUserCantLoginException();
		}
	}

	private void checkLoginUserMustchangepassword(final Credential credential,
	                                              final String userUUID) throws UserMustChangePasswordException {
		if (credential.isMustchangepassword()) {
			throw new UserMustChangePasswordException(userUUID);
		}
	}

	private void checkLoginUserBlocked(final Credential credential) throws BlockedUserCantLoginException {
		if (credential.getLogontrial() >= maxLogonTrial) {
			throw new BlockedUserCantLoginException();
		}
	}

	private void checkLoginUserNoCredential(final HttpServletRequest request,
	                                        final Credential credential,
	                                        final String what) throws UnknownUserCantLoginException {
		if (credential == null) {
			auditReportService.onRejectLogin(request, USER_NOT_FOUND, realm, what);
			throw new UnknownUserCantLoginException();
		}
	}

	private void checkPasswordDuringLogin(final HttpServletRequest request,
	                                      final LoginFormDto form,
	                                      final Credential credential) throws NoPasswordUserCantLoginException, BadPasswordUserCantLoginException {
		final var checkPasswordBadResult = checkPassword(form.getUserpassword(), credential);
		if (checkPasswordBadResult.isPresent()) {
			auditReportService.onRejectLogin(request, checkPasswordBadResult.get(), realm, form.getUserlogin());
			switch (checkPasswordBadResult.get()) {
			case MISSING_PASSWORD:
			case EMPTY_PASSWORD:
				throw new NoPasswordUserCantLoginException();
			default:
				credential.setLogontrial(credential.getLogontrial() + 1);
				credentialRepository.save(credential);
				throw new BadPasswordUserCantLoginException();
			}
		}
	}

	private Credential importLDAPUserFirstTime(final HttpServletRequest request,
	                                           final LoginFormDto form) throws UnknownUserCantLoginException {
		try {
			final var clientAddr = InetAddress.getByName(getOriginalRemoteAddr(request));
			if (externalAuthClientService.isIPAllowedToCreateUserAccount(clientAddr) == false) {
				throw new UnknownUserCantLoginException();
			}
			final var ldapUser = externalAuthClientService.logonUser(form.getUserlogin(), form.getUserpassword());
			final var userUUID = userDao.addLDAPUserCredential(ldapUser.getLogin(), ldapUser.getDomain(), realm)
			        .toString();
			return credentialRepository.getByUserUUID(userUUID);
		} catch (final UserCantLoginException | UnknownHostException e) {
			auditReportService.onRejectLogin(request, USER_NOT_FOUND, realm, form.getUserlogin());
			throw new UnknownUserCantLoginException();
		}
	}

	private void ldapLogon(final HttpServletRequest request,
	                       final LoginFormDto form,
	                       final Credential credential,
	                       final User user) throws UnknownUserCantLoginException {
		try {
			final var ldapUser = externalAuthClientService.logonUser(
			        credential.getLogin(), form.getUserpassword(), credential.getLdapdomain());

			setUserPrivacy(user.getUuid(), new UserPrivacyDto(ldapUser));
			/**
			 * Import ldapUser Groups to db
			 */
			final var groupNames = user.getGroups().stream().map(Group::getName)
			        .distinct().collect(toUnmodifiableSet());
			ldapUser.getGroups().forEach(ldapGroupName -> {
				if (groupNames.contains(ldapGroupName)) {
					return;
				}
				var group = groupRepository.getByName(ldapGroupName);
				if (group == null) {
					group = new Group(ldapGroupName);
					group.setDescription("Imported from LDAP");
					group = groupRepository.save(group);
					log.info("Create group \"{}\" from LDAP query", ldapGroupName);
				}
				user.getGroups().add(group);
			});
		} catch (final UserCantLoginException e) {
			auditReportService.onRejectLogin(request, USER_NOT_FOUND, realm, credential.getLogin());
			throw new UnknownUserCantLoginException();
		}
	}

	@Override
	@Transactional(readOnly = false)
	public void setupTOTPWithChecks(final ValidationSetupTOTPDto setupDto, final String expectedUserUUID) {
		final SetupTOTPTokenDto validatedToken;
		try {
			validatedToken = tokenService.setupTOTPExtractToken(setupDto.getControlToken());
		} catch (final NotAcceptableSecuredTokenException e) {
			log.error("Invalid token", e);
			throw new AuthKitException("You can't use this token");
		}
		if (expectedUserUUID.equalsIgnoreCase(validatedToken.getUserUUID()) == false) {
			throw new AuthKitException("You can't use this token for this user");
		}

		final var secret = TOTPServiceImpl.base32.decode(validatedToken.getSecret());
		if (totpService.isCodeIsValid(secret, setupDto.getTwoauthcode()) == false) {
			throw new AuthKitException("Invalid code");
		}

		final var credential = credentialRepository.getByUserUUID(expectedUserUUID);
		final var rejected = checkPassword(setupDto.getCurrentpassword(), credential);
		if (rejected.isPresent()) {
			throw new AuthKitException(SC_UNAUTHORIZED,
			        "Can't accept demand, bad password ; " + rejected.get().toString());
		}
		totpService.setupTOTP(validatedToken.getSecret(), validatedToken.getBackupCodes(), expectedUserUUID);
	}

	@Override
	@Transactional(readOnly = true)
	public void checkCodeAndPassword(final Credential credential, final ValidationTOTPDto validationDto) {
		final var optPassword = checkPassword(validationDto.getCurrentpassword(), credential);
		if (optPassword.isPresent()) {
			throw new AuthKitException(SC_UNAUTHORIZED, "Invalid password: " + optPassword.get());
		}
		try {
			totpService.checkCode(credential, validationDto.getTwoauthcode());
		} catch (final BadTOTPCodeCantLoginException e) {
			throw new AuthKitException(SC_UNAUTHORIZED, "Invalid 2auth code");
		}
	}

	@Override
	public LoginRequestContentDto userLoginRequest(final HttpServletRequest request,
	                                               final LoginFormDto form) throws UserCantLoginException {
		var credential = credentialRepository.getFromRealmLogin(realm, form.getUserlogin());
		if (credential == null && externalAuthClientService.isAvailable()) {
			credential = importLDAPUserFirstTime(request, form);
		}

		checkLoginUserNoCredential(request, credential, form.getUserlogin());
		checkLoginUserBlocked(credential);
		final var user = credential.getUser();
		checkLoginUserIsEnabled(request, credential, form.getUserlogin());

		if (credential.getLdapdomain() != null) {
			ldapLogon(request, form, credential, user);
		} else {
			checkPasswordDuringLogin(request, form, credential);
		}

		final var userUUID = user.getUuid();
		checkLoginUserMustchangepassword(credential, userUUID);
		final var totpKey = credential.getTotpkey();
		if (totpKey != null) {
			throw new TOTPUserCantLoginException(userUUID);
		}
		return prepareSessionToken(request, form.isShortSessionTime(), credential, userUUID);
	}

	private LoginRequestContentDto prepareSessionToken(final HttpServletRequest request,
	                                                   final boolean shortSessionTime,
	                                                   final Credential credential,
	                                                   final String userUUID) {
		final var clientAddr = getOriginalRemoteAddr(request);
		final var tags = Set.copyOf(userDao.getRightsForUser(userUUID, clientAddr));

		credential.setLastlogin(new Date());
		credential.setLogontrial(0);

		final Duration sessionDuration;
		if (shortSessionTime) {
			sessionDuration = shortSessionDuration;
		} else {
			sessionDuration = longSessionDuration;
		}

		String host;
		if (userDao.haveRightsForUserWithOnlyIP(userUUID, clientAddr)) {
			host = clientAddr;
		} else {
			host = null;
		}

		final var userSessionToken = tokenService.loggedUserRightsGenerateToken(
		        userUUID, sessionDuration, tags, host);
		final var cookie = cookieService.createLogonCookie(userSessionToken, sessionDuration);
		auditReportService.onLogin(request, longSessionDuration, tags);

		return new LoginRequestContentDto(userSessionToken, cookie);
	}

	@Override
	public LoginRequestContentDto userLoginRequest(final HttpServletRequest request,
	                                               final TOTPLogonCodeFormDto form) throws UserCantLoginException, NotAcceptableSecuredTokenException {
		final var userUUID = tokenService.userFormExtractTokenUUID(TOKEN_FORMNAME_ENTER_TOTP, form.getSecuretoken());
		final var credential = credentialRepository.getByUserUUID(userUUID);
		checkLoginUserNoCredential(request, credential, userUUID);
		checkLoginUserBlocked(credential);
		checkLoginUserIsEnabled(request, credential, userUUID);
		checkLoginUserMustchangepassword(credential, userUUID);

		try {
			totpService.checkCode(credential, form.getCode());
		} catch (final BadTOTPCodeCantLoginException e) {
			credential.setLogontrial(credential.getLogontrial() + 1);
			credentialRepository.save(credential);
			throw e;
		}
		return prepareSessionToken(request, form.getShorttime(), credential, userUUID);
	}

	@Override
	public String addUser(final AddUserDto addUser) {
		final var userLogin = addUser.getUserLogin();

		try {
			validPasswordPolicy.checkPasswordValidation(addUser, DEFAULT);
		} catch (final PasswordComplexityException e) {
			throw new AuthKitException("Invalid new password: " + e.getMessage());
		}

		final var previousUser = credentialRepository.getFromRealmLogin(realm, userLogin);
		if (previousUser != null) {
			throw new AuthKitException("User \"" + addUser.getUserLogin() + "\" actually exists");
		}

		final var hashedPassword = addUser.getUserPassword().hash(
		        userPassword -> ARGON2.hash(iterations, memory, parallelism, userPassword));
		final var cipherHashedPassword = cipherService.cipherFromString(hashedPassword);
		final var userUUID = userDao.addUserCredential(userLogin, cipherHashedPassword, realm).toString();

		log.info("Add user {} [{}]", userLogin, userUUID);
		return userUUID;
	}

	@Override
	public void removeUser(final String userUUID) {
		getUserByUUID(userUUID);
		log.info("Remove user {}", userUUID);
		userDao.deleteUser(UUID.fromString(userUUID));
	}

	@Override
	public void disableUser(final String userUUID) {
		final var user = getUserByUUID(userUUID);
		log.info("Disable user {}", userUUID);
		final var credential = user.getCredential();
		Objects.requireNonNull(credential, MSG_CANT_FOUND_CREDENTIAL_FOR_USER + userUUID);
		credential.setEnabled(false);
		credentialRepository.save(credential);
	}

	@Override
	public void enableUser(final String userUUID) {
		final var user = getUserByUUID(userUUID);
		log.info("Enable user {}", userUUID);
		final var credential = user.getCredential();
		Objects.requireNonNull(credential, MSG_CANT_FOUND_CREDENTIAL_FOR_USER + userUUID);
		credential.setEnabled(true);
		credentialRepository.save(credential);
	}

	@Override
	public void resetUserLogonTrials(final String userUUID) {
		final var user = getUserByUUID(userUUID);
		log.info("Reset user logon trials {}", userUUID);
		final var credential = user.getCredential();
		Objects.requireNonNull(credential, MSG_CANT_FOUND_CREDENTIAL_FOR_USER + userUUID);
		credential.setLogontrial(0);
		credentialRepository.save(credential);
	}

	@Override
	public void setUserMustChangePassword(final String userUUID) {
		final var user = getUserByUUID(userUUID);
		log.info("Switch user must change password {}", userUUID);
		final var credential = user.getCredential();
		Objects.requireNonNull(credential, MSG_CANT_FOUND_CREDENTIAL_FOR_USER + userUUID);
		credential.setMustchangepassword(true);
		credentialRepository.save(credential);
	}

	@Override
	public void changeUserPassword(final String userUUID,
	                               final Password newPassword) throws ResetWithSamePasswordException, BlockedUserException {
		Objects.requireNonNull(newPassword, "No password enter");
		final var user = getUserByUUID(userUUID);
		final var credential = user.getCredential();
		Objects.requireNonNull(credential, MSG_CANT_FOUND_CREDENTIAL_FOR_USER + userUUID);

		if (credential.getLogontrial() >= maxLogonTrial) {
			throw new BlockedUserException();
		}

		try {
			validPasswordPolicy.checkPasswordValidation(credential.getLogin(), newPassword, DEFAULT);
		} catch (final PasswordComplexityException e) {
			throw new AuthKitException("Invalid new password: " + e.getMessage());
		}

		/**
		 * Test if user change with the same password
		 */
		final var newPasswordForChecks = newPassword.duplicate();
		final var passwordHashCheck = cipherService.unCipherToString(credential.getPasswordhash());
		if (newPasswordForChecks.verify(ARGON2, passwordHashCheck)) {
			throw new ResetWithSamePasswordException();
		}

		final var newHashedPassword = newPassword.hash(
		        userPassword -> ARGON2.hash(iterations, memory, parallelism, userPassword));
		final var newCipherHashedPassword = cipherService.cipherFromString(newHashedPassword);
		credential.setPasswordhash(newCipherHashedPassword);
		credential.setMustchangepassword(false);
		log.info("User change password {}", userUUID);
		credentialRepository.save(credential);
	}

	@Override
	public List<String> getRightsForUser(final String userUUID, final String clientAddr) {
		return userDao.getRightsForUser(userUUID, clientAddr);
	}

	@Override
	public List<String> getContextRightsForUser(final String userUUID,
	                                            final String clientAddr,
	                                            final String rightName) {
		return userDao.getContextRightsForUser(userUUID, clientAddr, rightName);
	}

	@Override
	public boolean isUserEnabledAndNonBlocked(final String userUUID) {
		final var credential = credentialRepository.getByUserUUID(userUUID);
		return (credential == null
		        || credential.isEnabled() == false
		        || credential.isMustchangepassword()
		        || credential.getLogontrial() >= maxLogonTrial) == false;
	}

	////////// Group zone

	@Override
	public void addGroup(final AddGroupOrRoleDto newGroup) {
		final var name = newGroup.getName();
		if (groupRepository.getByName(name) != null) {
			return;
		}

		final var group = new Group(name);
		group.setDescription(newGroup.getDescription());
		groupRepository.save(group);
		log.info("Create group \"{}\"", name);
	}

	@Override
	public void renameGroup(final RenameGroupOrRoleDto renameGroup) {
		final var name = renameGroup.getName();
		getGroupByName(name).setName(renameGroup.getNewname());
		log.info("Rename group \"{}\" to \"{}\"", name, renameGroup.getNewname());
	}

	@Override
	public void setGroupDescription(final AddGroupOrRoleDto changeGroup) {
		final var name = changeGroup.getName();
		getGroupByName(name).setDescription(changeGroup.getDescription());
		log.info(() -> "Change role \"" + name + "\" description to \""
		               + sanitize(changeGroup.getDescription()) + "\"");
	}

	@Override
	public void addUserInGroup(final String userUUID, final String groupName) {
		getUserByUUID(userUUID).getGroups().add(getGroupByName(groupName));
		log.info("Add user {} in group \"{}\"", userUUID, groupName);
	}

	@Override
	public void removeUserInGroup(final String userUUID, final String groupName) {
		getUserByUUID(userUUID).getGroups().remove(getGroupByName(groupName));
		log.info("Remove user {} from group \"{}\"", userUUID, groupName);
	}

	@Override
	public void removeGroup(final String groupName) {
		groupRepository.delete(getGroupByName(groupName));
		log.info("Remove group \"{}\"", groupName);
	}

	@Override
	public List<GroupOrRoleDto> listAllGroups() {
		return groupRepository.findAll().stream().map(GroupOrRoleDto::new)
		        .collect(Collectors.toUnmodifiableList());
	}

	@Override
	public List<GroupOrRoleDto> listGroupsForUser(final String userUUID) {
		return groupRepository.getByUserUUID(userUUID).stream().map(GroupOrRoleDto::new)
		        .collect(Collectors.toUnmodifiableList());
	}

	////////// Role zone

	@Override
	public void addRole(final AddGroupOrRoleDto newRole) {
		final var name = newRole.getName();
		if (roleRepository.getByName(name) != null) {
			return;
		}

		final var role = new Role(name);
		role.setDescription(newRole.getDescription());
		roleRepository.save(role);
		log.info("Create role \"{}\"", name);
	}

	@Override
	public void renameRole(final RenameGroupOrRoleDto renameRole) {
		final var name = renameRole.getName();
		getRoleByName(name).setName(renameRole.getNewname());
		log.info("Rename role \"{}\" to \"{}\"", name, renameRole.getNewname());
	}

	@Override
	public void setRoleDescription(final AddGroupOrRoleDto changeRole) {
		final var name = changeRole.getName();
		final var role = getRoleByName(name);
		role.setDescription(changeRole.getDescription());
		log.info(() -> "Change role \"" + name + "\" description to \""
		               + sanitize(changeRole.getDescription()) + "\"");
	}

	@Override
	public void setRoleOnlyForClient(final String roleName, final String ipAddr) {
		try {
			final var addr = InetAddress.getByName(ipAddr).getHostAddress().toLowerCase();
			roleRepository.getByName(roleName).setOnlyforclient(addr);
			log.info("Change role \"{}\" IP restriction to \"{}\"", roleName, addr);
		} catch (final UnknownHostException e) {
			throw new IllegalArgumentException("Invalid IP Addr", e);
		}
	}

	@Override
	public void addGroupInRole(final String groupName, final String roleName) {
		getGroupByName(groupName).getRoles().add(getRoleByName(roleName));
		log.info("Add role {} in group \"{}\"", roleName, groupName);
	}

	@Override
	public void removeGroupInRole(final String groupName, final String roleName) {
		getGroupByName(groupName).getRoles().remove(getRoleByName(roleName));
		log.info("Remove role {} from group \"{}\"", roleName, groupName);
	}

	@Override
	public void removeRole(final String roleName) {
		roleRepository.delete(getRoleByName(roleName));
		log.info("Remove role \"{}\"", roleName);
	}

	@Override
	public List<GroupOrRoleDto> listAllRoles() {
		return roleRepository.findAll().stream().map(GroupOrRoleDto::new)
		        .collect(Collectors.toUnmodifiableList());
	}

	@Override
	public List<GroupOrRoleDto> listRolesForGroup(final String groupName) {
		return roleRepository.getByGroupName(groupName).stream().map(GroupOrRoleDto::new)
		        .collect(Collectors.toUnmodifiableList());
	}

	////////// Rights zone

	@Override
	public void addRightInRole(final String roleName, final String rightName) {
		final var role = getRoleByName(roleName);
		if (role.getRoleRights().stream().anyMatch(r -> r.getName().equals(rightName))) {
			return;
		}

		final var rr = new RoleRight(rightName, role);
		roleRightRepository.save(rr);
		log.info("Add right \"{}\" in role \"{}\"", rightName, roleName);
	}

	@Override
	public void removeRightInRole(final String roleName, final String rightName) {
		final var role = getRoleByName(roleName);
		role.getRoleRights().removeIf(r -> r.getName().equals(rightName));
		log.info("Remove right \"{}\" from role \"{}\"", rightName, roleName);
	}

	@Override
	public Set<String> getAllRights() {
		return authKitEndpointsListener.getAllRights();
	}

	@Override
	public List<String> listRightsForRole(final String roleName) {
		return roleRightRepository.getRoleRightNamesByRoleName(roleName);
	}

	////////// Contexts right zone

	@Override
	public void addContextInRight(final String roleName, final String rightName, final String context) {
		if (roleRightContextRepository.countContextPresenceForRightRole(roleName, rightName, context) > 0) {
			return;
		}
		final var rrc = new RoleRightContext(context, getRoleRight(roleName, rightName));
		roleRightContextRepository.save(rrc);
		log.info("Add right context {} for right \"{}\" in role \"{}\"", context, rightName, roleName);
	}

	@Override
	public void removeContextInRight(final String roleName, final String rightName, final String context) {
		if (roleRightContextRepository.countContextPresenceForRightRole(roleName, rightName, context) == 0) {
			return;
		}
		getRoleRight(roleName, rightName).getRoleRightContexts().removeIf(rrc -> rrc.getName().equals(context));
		log.info("Remove right context {} from right \"{}\" in role \"{}\"", context, rightName, roleName);
	}

	@Override
	public List<String> listContextsForRight(final String roleName, final String rightName) {
		return roleRightContextRepository.listContextsForRightRole(roleName, rightName);
	}

	////////// Reverse searchs

	@Override
	public List<UserDto> listLinkedUsersForGroup(final String groupName) {
		return getGroupByName(groupName).getUsers().stream().map(UserDto::new)
		        .collect(Collectors.toUnmodifiableList());
	}

	@Override
	public List<GroupOrRoleDto> listLinkedGroupsForRole(final String roleName) {
		return getRoleByName(roleName).getGroups().stream().map(GroupOrRoleDto::new)
		        .collect(Collectors.toUnmodifiableList());
	}

	/////////// UserPrivacy

	@Override
	public List<UserPrivacyDto> getUserPrivacyList(final Collection<String> userUUIDList) {
		final Function<byte[], String> unCipher = ciphered -> {
			if (ciphered == null) {
				return null;
			}
			return cipherService.unCipherToString(ciphered);
		};
		return userPrivacyRepository.getByUserUUID(userUUIDList).stream()
		        .map(up -> new UserPrivacyDto(up, unCipher)).collect(Collectors.toUnmodifiableList());
	}

	@Override
	public void setUserPrivacy(final String userUUID, final UserPrivacyDto userPrivacyDto) {
		var currentItem = userPrivacyRepository.getByUserUUID(userUUID);
		if (currentItem == null) {
			currentItem = new Userprivacy(userUUID);
		}
		userPrivacyDto.mergue(currentItem, noncipher -> cipherService.cipherFromString(noncipher));

		if (userPrivacyDto.getEmail() != null) {
			currentItem.setHashedEmail(cipherService.computeSHA3FromString(userPrivacyDto.getEmail()));
		}

		userPrivacyRepository.save(currentItem);
	}

}
