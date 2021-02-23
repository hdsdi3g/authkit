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
package tv.hd3g.authkit.mod.controller;

import static javax.servlet.http.HttpServletResponse.SC_NOT_FOUND;
import static org.owasp.encoder.Encode.forJavaScript;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.HttpStatus.PARTIAL_CONTENT;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static tv.hd3g.authkit.utility.LogSanitizer.sanitize;

import java.util.List;
import java.util.UUID;

import javax.validation.constraints.NotEmpty;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import tv.hd3g.authkit.mod.dto.ressource.CreatedUserDto;
import tv.hd3g.authkit.mod.dto.ressource.GroupOrRoleDto;
import tv.hd3g.authkit.mod.dto.ressource.ItemListDto;
import tv.hd3g.authkit.mod.dto.ressource.UserDto;
import tv.hd3g.authkit.mod.dto.ressource.UserPrivacyDto;
import tv.hd3g.authkit.mod.dto.validated.AddGroupOrRoleDto;
import tv.hd3g.authkit.mod.dto.validated.AddUserDto;
import tv.hd3g.authkit.mod.dto.validated.ChangeIPDto;
import tv.hd3g.authkit.mod.dto.validated.ListStringDto;
import tv.hd3g.authkit.mod.dto.validated.RenameGroupOrRoleDto;
import tv.hd3g.authkit.mod.exception.AuthKitException;
import tv.hd3g.authkit.mod.repository.UserDao;
import tv.hd3g.authkit.mod.repository.UserRepository;
import tv.hd3g.authkit.mod.service.AuthenticationService;
import tv.hd3g.commons.authkit.AuditAfter;
import tv.hd3g.commons.authkit.CheckBefore;

@RestController
@RequestMapping(value = "/v1/authkit", produces = APPLICATION_JSON_VALUE)
@CheckBefore("SecurityAdmin")
public class RestControllerUser {

	@Autowired
	private AuthenticationService authenticationService;
	@Autowired
	private UserDao userDao;
	@Autowired
	private UserRepository userRepository;

	@Value("${authkit.dbMaxFetchSize:50}")
	private int dbMaxFetchSize;
	@Value("${authkit.realm:default}")
	private String realm;

	@Transactional(readOnly = false)
	@PostMapping(value = "users")
	@AuditAfter(value = "addUser", changeSecurity = true)
	public ResponseEntity<CreatedUserDto> addUser(@RequestBody @Validated final AddUserDto addUser) {
		final var uuid = authenticationService.addUser(addUser);
		final var result = new CreatedUserDto(forJavaScript(addUser.getUserLogin()), uuid, realm);
		return new ResponseEntity<>(result, CREATED);
	}

	@Transactional(readOnly = true)
	@GetMapping(value = "users/{uuid}")
	@AuditAfter(value = "getUser", changeSecurity = false)
	public ResponseEntity<UserDto> getUser(@PathVariable("uuid") @NotEmpty final String _uuid) {
		final var uuid = sanitize(_uuid);
		final var result = userDao.getUserByUUID(UUID.fromString(uuid))
		        .orElseThrow(() -> new AuthKitException(SC_NOT_FOUND, "Can't found user " + uuid));
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = true)
	@GetMapping(value = "users")
	@AuditAfter(value = "listUser", changeSecurity = false)
	public ResponseEntity<ItemListDto<UserDto>> listUsers(@RequestParam(defaultValue = "0") final int pos,
	                                                      @RequestParam(defaultValue = "0") final int size) {
		final var total = (int) userRepository.count();
		final int limit;
		final int selectedPos;
		final List<UserDto> list;
		if (total == 0) {
			limit = 0;
			selectedPos = 0;
			list = List.of();
		} else {
			if (size < 1) {
				limit = dbMaxFetchSize;
			} else {
				limit = Math.min(total, Math.min(dbMaxFetchSize, size));
			}
			selectedPos = Math.min(total - 1, Math.max(0, pos));
			list = userDao.getUserList(selectedPos, limit);
		}
		final var result = new ItemListDto<>(list);

		final var headers = new LinkedMultiValueMap<String, String>();
		headers.add("Content-Range", selectedPos + "-" + limit + "/" + total);
		headers.add("Accept-Range", "user " + dbMaxFetchSize);

		if (list.size() == total) {
			return new ResponseEntity<>(result, headers, OK);
		}
		return new ResponseEntity<>(result, headers, PARTIAL_CONTENT);
	}

	@Transactional(readOnly = false)
	@PutMapping(value = "users/{uuid}/disable")
	@AuditAfter(value = "disableUser", changeSecurity = true)
	public ResponseEntity<Object> disableUser(@PathVariable("uuid") @NotEmpty final String _uuid) {
		final var uuid = sanitize(_uuid);
		authenticationService.disableUser(uuid);
		return new ResponseEntity<>(OK);
	}

	@Transactional(readOnly = false)
	@PutMapping(value = "users/{uuid}/enable")
	@AuditAfter(value = "enableUser", changeSecurity = true)
	public ResponseEntity<Object> enableUser(@PathVariable("uuid") @NotEmpty final String _uuid) {
		final var uuid = sanitize(_uuid);
		authenticationService.enableUser(uuid);
		return new ResponseEntity<>(OK);
	}

	@Transactional(readOnly = false)
	@PutMapping(value = "users/{uuid}/switchresetpassword")
	@AuditAfter(value = "switchUserMustResetPassword", changeSecurity = true)
	public ResponseEntity<Object> switchUserMustResetPassword(@PathVariable("uuid") @NotEmpty final String _uuid) {
		final var uuid = sanitize(_uuid);
		authenticationService.setUserMustChangePassword(uuid);
		return new ResponseEntity<>(OK);
	}

	@Transactional(readOnly = false)
	@PutMapping(value = "users/{uuid}/resetlogontrials")
	@AuditAfter(value = "resetUserLogonTrials", changeSecurity = true)
	public ResponseEntity<Object> resetUserLogonTrials(@PathVariable("uuid") @NotEmpty final String _uuid) {
		final var uuid = sanitize(_uuid);
		authenticationService.resetUserLogonTrials(uuid);
		return new ResponseEntity<>(OK);
	}

	@Transactional(readOnly = false)
	@DeleteMapping(value = "users/{uuid}")
	@AuditAfter(value = "removeUser", changeSecurity = true)
	public ResponseEntity<Object> removeUser(@PathVariable("uuid") @NotEmpty final String _uuid) {
		final var uuid = sanitize(_uuid);
		authenticationService.removeUser(uuid);
		return new ResponseEntity<>(OK);
	}

	////////// Group zone

	@Transactional(readOnly = false)
	@AuditAfter(value = "addGroup", changeSecurity = true)
	@PostMapping(value = "groups")
	public ResponseEntity<Object> addGroup(@RequestBody @Validated final AddGroupOrRoleDto newGroup) {
		authenticationService.addGroup(newGroup);
		return new ResponseEntity<>(CREATED);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "renameGroup", changeSecurity = true)
	@PostMapping(value = "groups/rename")
	public ResponseEntity<Object> renameGroup(@RequestBody @Validated final RenameGroupOrRoleDto renameGroup) {
		authenticationService.renameGroup(renameGroup);
		return new ResponseEntity<>(OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "setGroupDescription", changeSecurity = true)
	@PutMapping(value = "groups/description")
	public ResponseEntity<Object> setGroupDescription(@RequestBody @Validated final AddGroupOrRoleDto changeGroup) {
		authenticationService.setGroupDescription(changeGroup);
		return new ResponseEntity<>(OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "addUserInGroup", changeSecurity = true)
	@PostMapping(value = "users/{uuid}/ingroup/{name}")
	public ResponseEntity<Object> addUserInGroup(@PathVariable("uuid") @NotEmpty final String _userUUID,
	                                             @PathVariable("name") @NotEmpty final String _groupName) {
		final var userUUID = sanitize(_userUUID);
		final var groupName = sanitize(_groupName);
		authenticationService.addUserInGroup(userUUID, groupName);
		return new ResponseEntity<>(CREATED);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "removeUserInGroup", changeSecurity = true)
	@DeleteMapping(value = "users/{uuid}/ingroup/{name}")
	public ResponseEntity<Object> removeUserInGroup(@PathVariable("uuid") @NotEmpty final String _userUUID,
	                                                @PathVariable("name") @NotEmpty final String _groupName) {
		final var userUUID = sanitize(_userUUID);
		final var groupName = sanitize(_groupName);
		authenticationService.removeUserInGroup(userUUID, groupName);
		return new ResponseEntity<>(OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "removeGroup", changeSecurity = true)
	@DeleteMapping(value = "groups/{name}")
	public ResponseEntity<Object> removeGroup(@PathVariable("name") @NotEmpty final String _groupName) {
		final var groupName = sanitize(_groupName);
		authenticationService.removeGroup(groupName);
		return new ResponseEntity<>(OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "listAllGroups", changeSecurity = false)
	@GetMapping(value = "groups")
	public ResponseEntity<ItemListDto<GroupOrRoleDto>> listAllGroups() {
		final var result = new ItemListDto<>(authenticationService.listAllGroups());
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "listGroupsForUser", changeSecurity = false)
	@GetMapping(value = "users/{uuid}/groups")
	public ResponseEntity<ItemListDto<GroupOrRoleDto>> listGroupsForUser(@PathVariable("uuid") @NotEmpty final String _userUUID) {
		final var userUUID = sanitize(_userUUID);
		final var result = new ItemListDto<>(authenticationService.listGroupsForUser(userUUID));
		return new ResponseEntity<>(result, OK);
	}

	////////// Role zone

	@Transactional(readOnly = false)
	@AuditAfter(value = "addRole", changeSecurity = true)
	@PostMapping(value = "roles")
	public ResponseEntity<Object> addRole(@RequestBody @Validated final AddGroupOrRoleDto newRole) {
		authenticationService.addRole(newRole);
		return new ResponseEntity<>(CREATED);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "renameRole", changeSecurity = true)
	@PostMapping(value = "roles/rename")
	public ResponseEntity<Object> renameRole(@RequestBody @Validated final RenameGroupOrRoleDto renameRole) {
		authenticationService.renameRole(renameRole);
		return new ResponseEntity<>(OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "setRoleDescription", changeSecurity = true)
	@PutMapping(value = "roles/description")
	public ResponseEntity<Object> setRoleDescription(@RequestBody @Validated final AddGroupOrRoleDto changeRole) {
		authenticationService.setRoleDescription(changeRole);
		return new ResponseEntity<>(OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "setRoleOnlyForClients", changeSecurity = true)
	@PutMapping(value = "roles/{rolename}/setOnlyForClient")
	public ResponseEntity<Object> setRoleOnlyForClient(@PathVariable("rolename") @NotEmpty final String _roleName,
	                                                   @RequestBody @Validated final ChangeIPDto setIp) {
		final var roleName = sanitize(_roleName);
		authenticationService.setRoleOnlyForClient(roleName, setIp.getIp());
		return new ResponseEntity<>(OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "addGroupInRole", changeSecurity = true)
	@PostMapping(value = "groups/{groupname}/inrole/{rolename}")
	public ResponseEntity<Object> addGroupInRole(@PathVariable("groupname") @NotEmpty final String _groupName,
	                                             @PathVariable("rolename") @NotEmpty final String _roleName) {
		final var roleName = sanitize(_roleName);
		final var groupName = sanitize(_groupName);
		authenticationService.addGroupInRole(groupName, roleName);
		return new ResponseEntity<>(CREATED);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "removeGroupInRole", changeSecurity = true)
	@DeleteMapping(value = "groups/{groupname}/inrole/{rolename}")
	public ResponseEntity<Object> removeGroupInRole(@PathVariable("groupname") @NotEmpty final String _groupName,
	                                                @PathVariable("rolename") @NotEmpty final String _roleName) {
		final var roleName = sanitize(_roleName);
		final var groupName = sanitize(_groupName);
		authenticationService.removeGroupInRole(groupName, roleName);
		return new ResponseEntity<>(OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "removeRole", changeSecurity = true)
	@DeleteMapping(value = "roles/{rolename}")
	public ResponseEntity<Object> removeRole(@PathVariable("rolename") @NotEmpty final String _roleName) {
		final var roleName = sanitize(_roleName);
		authenticationService.removeRole(roleName);
		return new ResponseEntity<>(OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "listAllRoles", changeSecurity = false)
	@GetMapping(value = "roles")
	public ResponseEntity<ItemListDto<GroupOrRoleDto>> listAllRoles() {
		final var result = new ItemListDto<>(authenticationService.listAllRoles());
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "listRolesForGroup", changeSecurity = false)
	@GetMapping(value = "groups/{groupname}/roles")
	public ResponseEntity<ItemListDto<GroupOrRoleDto>> listRolesForGroup(@PathVariable("groupname") @NotEmpty final String _groupName) {
		final var groupName = sanitize(_groupName);
		final var result = new ItemListDto<>(authenticationService.listRolesForGroup(groupName));
		return new ResponseEntity<>(result, OK);
	}

	////////// Rights zone

	@Transactional(readOnly = false)
	@AuditAfter(value = "addRightInRole", changeSecurity = true)
	@PostMapping(value = "roles/{rolename}/rights/{rightname}")
	public ResponseEntity<Object> addRightInRole(@PathVariable("rolename") @NotEmpty final String _roleName,
	                                             @PathVariable("rightname") @NotEmpty final String _rightName) {
		final var roleName = sanitize(_roleName);
		final var rightName = sanitize(_rightName);
		authenticationService.addRightInRole(roleName, rightName);
		return new ResponseEntity<>(CREATED);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "removeRightInRole", changeSecurity = true)
	@DeleteMapping(value = "roles/{rolename}/rights/{rightname}")
	public ResponseEntity<Object> removeRightInRole(@PathVariable("rolename") @NotEmpty final String _roleName,
	                                                @PathVariable("rightname") @NotEmpty final String _rightName) {
		final var roleName = sanitize(_roleName);
		final var rightName = sanitize(_rightName);
		authenticationService.removeRightInRole(roleName, rightName);
		return new ResponseEntity<>(OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "getAllRights", changeSecurity = false)
	@GetMapping(value = "rights")
	public ResponseEntity<ItemListDto<String>> getAllRights() {
		final var result = new ItemListDto<>(authenticationService.getAllRights());
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "listRightsForRole", changeSecurity = false)
	@GetMapping(value = "roles/{rolename}/rights")
	public ResponseEntity<ItemListDto<String>> listRightsForRole(@PathVariable("rolename") @NotEmpty final String _roleName) {
		final var roleName = sanitize(_roleName);
		final var result = new ItemListDto<>(authenticationService.listRightsForRole(roleName));
		return new ResponseEntity<>(result, OK);
	}

	////////// Contexts right zone

	@Transactional(readOnly = false)
	@AuditAfter(value = "addContextInRight", changeSecurity = true)
	@PostMapping(value = "roles/{rolename}/rights/{rightname}/contexts/{context}")
	public ResponseEntity<Object> addContextInRight(@PathVariable("rolename") @NotEmpty final String _roleName,
	                                                @PathVariable("rightname") @NotEmpty final String _rightName,
	                                                @PathVariable("context") @NotEmpty final String _context) {
		final var roleName = sanitize(_roleName);
		final var rightName = sanitize(_rightName);
		final var context = sanitize(_context);
		authenticationService.addContextInRight(roleName, rightName, context);
		return new ResponseEntity<>(CREATED);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "removeContextInRight", changeSecurity = true)
	@DeleteMapping(value = "roles/{rolename}/rights/{rightname}/contexts/{context}")
	public ResponseEntity<Object> removeContextInRight(@PathVariable("rolename") @NotEmpty final String _roleName,
	                                                   @PathVariable("rightname") @NotEmpty final String _rightName,
	                                                   @PathVariable("context") @NotEmpty final String _context) {
		final var roleName = sanitize(_roleName);
		final var rightName = sanitize(_rightName);
		final var context = sanitize(_context);
		authenticationService.removeContextInRight(roleName, rightName, context);

		return new ResponseEntity<>(OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "listContextsForRight", changeSecurity = false)
	@GetMapping(value = "roles/{rolename}/rights/{rightname}/contexts")
	public ResponseEntity<ItemListDto<String>> listContextsForRight(@PathVariable("rolename") @NotEmpty final String _roleName,
	                                                                @PathVariable("rightname") @NotEmpty final String _rightName) {
		final var roleName = sanitize(_roleName);
		final var rightName = sanitize(_rightName);
		final var result = new ItemListDto<>(authenticationService.listContextsForRight(roleName, rightName));
		return new ResponseEntity<>(result, OK);
	}

	////////// Reverse searchs

	@Transactional(readOnly = false)
	@AuditAfter(value = "listLinkedUsersForGroup", changeSecurity = false)
	@GetMapping(value = "groups/{name}/users")
	public ResponseEntity<ItemListDto<UserDto>> listLinkedUsersForGroup(@PathVariable("name") @NotEmpty final String _groupName) {
		final var groupName = sanitize(_groupName);
		final var result = new ItemListDto<>(authenticationService.listLinkedUsersForGroup(groupName));
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "listLinkedGroupsForRole", changeSecurity = false)
	@GetMapping(value = "roles/{name}/groups")
	public ResponseEntity<ItemListDto<GroupOrRoleDto>> listLinkedGroupsForRole(@PathVariable("name") @NotEmpty final String _roleName) {
		final var roleName = sanitize(_roleName);
		final var result = new ItemListDto<>(authenticationService.listLinkedGroupsForRole(roleName));
		return new ResponseEntity<>(result, OK);
	}

	/////////// UserPrivacy

	@Transactional(readOnly = true)
	@GetMapping(value = "users/{uuid}/privacy")
	@AuditAfter(value = "getUserPrivacy", changeSecurity = false)
	public ResponseEntity<UserPrivacyDto> getUserPrivacy(@PathVariable("uuid") @NotEmpty final String _uuid) {
		final var uuid = sanitize(_uuid);
		final var list = authenticationService.getUserPrivacyList(List.of(uuid));
		UserPrivacyDto result;
		if (list.isEmpty()) {
			result = new UserPrivacyDto();
		} else {
			result = list.get(0);
		}
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = true)
	@GetMapping(value = "users/privacy")
	@AuditAfter(value = "getUsersPrivacy", changeSecurity = false)
	public ResponseEntity<ItemListDto<UserPrivacyDto>> getUsersPrivacy(@RequestBody @Validated final ListStringDto userUUIDList) {
		final var list = authenticationService.getUserPrivacyList(userUUIDList.getList());
		final var result = new ItemListDto<>(list);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@PutMapping(value = "users/{uuid}/privacy")
	@AuditAfter(value = "setUserPrivacy", changeSecurity = true)
	public ResponseEntity<Object> setUserPrivacy(@RequestBody @Validated final UserPrivacyDto userPrivacyDto,
	                                             @PathVariable("uuid") @NotEmpty final String _userUUID) {
		final var userUUID = sanitize(_userUUID);
		authenticationService.setUserPrivacy(userUUID, userPrivacyDto);
		return new ResponseEntity<>(OK);
	}
}
