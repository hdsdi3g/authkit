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

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import tv.hd3g.authkit.mod.dto.LoginRequestContentDto;
import tv.hd3g.authkit.mod.dto.Password;
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
import tv.hd3g.authkit.mod.exception.BlockedUserException;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException;
import tv.hd3g.authkit.mod.exception.ResetWithSamePasswordException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException;
import tv.hd3g.authkit.mod.service.AuditReportService.RejectLoginCause;

public interface AuthenticationService {

	////////// User zone

	/**
	 * @param request (used by Audit)
	 * @return sessionToken String
	 */
	LoginRequestContentDto userLoginRequest(HttpServletRequest request,
	                                        LoginFormDto form) throws UserCantLoginException;

	/**
	 * @param request (used by Audit)
	 * @return sessionToken String
	 */
	LoginRequestContentDto userLoginRequest(HttpServletRequest request,
	                                        TOTPLogonCodeFormDto form) throws UserCantLoginException, NotAcceptableSecuredTokenException;

	Optional<RejectLoginCause> checkPassword(Password userEnterPassword, Credential credential);

	void checkCodeAndPassword(Credential credential, ValidationTOTPDto validationDto);

	/**
	 * @return userUUID
	 */
	String addUser(AddUserDto addUser);

	void removeUser(String userUUID);

	void disableUser(String userUUID);

	void enableUser(String userUUID);

	void resetUserLogonTrials(String userUUID);

	boolean isUserEnabledAndNonBlocked(String userUUID);

	void setUserMustChangePassword(String userUUID);

	void changeUserPassword(String userUUID,
	                        Password newPassword) throws ResetWithSamePasswordException, BlockedUserException;

	List<String> getRightsForUser(String userUUID, String clientAddr);

	List<String> getContextRightsForUser(String userUUID, String clientAddr, String rightName);

	void setupTOTPWithChecks(ValidationSetupTOTPDto setupDto, String expectedUserUUID);

	////////// Group zone

	void addGroup(AddGroupOrRoleDto newGroup);

	void renameGroup(RenameGroupOrRoleDto renameGroup);

	void setGroupDescription(AddGroupOrRoleDto changeGroup);

	void addUserInGroup(String userUUID, String groupName);

	void removeUserInGroup(String userUUID, String groupName);

	void removeGroup(String groupName);

	List<GroupOrRoleDto> listAllGroups();

	List<GroupOrRoleDto> listGroupsForUser(String userUUID);

	////////// Role zone

	void addRole(AddGroupOrRoleDto newRole);

	void renameRole(RenameGroupOrRoleDto renameRole);

	void setRoleDescription(AddGroupOrRoleDto changeRole);

	void setRoleOnlyForClient(String roleName, String ipAddr);

	void addGroupInRole(String groupName, String roleName);

	void removeGroupInRole(String groupName, String roleName);

	void removeRole(String roleName);

	List<GroupOrRoleDto> listAllRoles();

	List<GroupOrRoleDto> listRolesForGroup(String groupName);

	////////// Rights zone

	void addRightInRole(String roleName, String rightName);

	void removeRightInRole(String roleName, String rightName);

	Set<String> getAllRights();

	List<String> listRightsForRole(String roleName);

	////////// Contexts right zone

	void addContextInRight(String roleName, String rightName, String context);

	void removeContextInRight(String roleName, String rightName, String context);

	List<String> listContextsForRight(String roleName, String rightName);

	////////// Reverse searchs

	List<UserDto> listLinkedUsersForGroup(String groupName);

	List<GroupOrRoleDto> listLinkedGroupsForRole(String roleName);

	/////////// UserPrivacy

	List<UserPrivacyDto> getUserPrivacyList(Collection<String> userUUIDList);

	void setUserPrivacy(String userUUID, UserPrivacyDto userPrivacyDto);

}
