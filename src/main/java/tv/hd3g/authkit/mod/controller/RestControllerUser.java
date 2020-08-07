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
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.linkTo;
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.methodOn;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.HttpStatus.PARTIAL_CONTENT;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.web.bind.annotation.RequestMethod.DELETE;
import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;
import static org.springframework.web.bind.annotation.RequestMethod.PUT;
import static tv.hd3g.authkit.mod.LogSanitizer.sanitize;

import java.util.List;
import java.util.UUID;
import java.util.function.Function;

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
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import tv.hd3g.authkit.mod.dto.ressource.BaseRepresentationModel;
import tv.hd3g.authkit.mod.dto.ressource.CreatedUserDto;
import tv.hd3g.authkit.mod.dto.ressource.GroupOrRoleDto;
import tv.hd3g.authkit.mod.dto.ressource.ItemListDto;
import tv.hd3g.authkit.mod.dto.ressource.UserDto;
import tv.hd3g.authkit.mod.dto.ressource.UserPrivacyDto;
import tv.hd3g.authkit.mod.dto.ressource.WsDtoLink;
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

	private static final String HATEOAS_REMOVE = "remove";
	private static final String HATEOAS_DEFAULT_GROUP_NAME = "group-name";
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
		createHateoasLinksForUser(uuid, result);
		return new ResponseEntity<>(result, CREATED);
	}

	@Transactional(readOnly = true)
	@GetMapping(value = "users/{uuid}")
	@AuditAfter(value = "getUser", changeSecurity = false)
	public ResponseEntity<UserDto> getUser(@PathVariable("uuid") @NotEmpty final String _uuid) {
		final var uuid = sanitize(_uuid);
		final var result = userDao.getUserByUUID(UUID.fromString(uuid))
		        .orElseThrow(() -> new AuthKitException(SC_NOT_FOUND, "Can't found user " + uuid));

		createHateoasLinksForUser(uuid, result);
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
		createHateoasLinksForUser("<UUID>", result);

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
	public ResponseEntity<BaseRepresentationModel> disableUser(@PathVariable("uuid") @NotEmpty final String _uuid) {
		final var uuid = sanitize(_uuid);
		authenticationService.disableUser(uuid);

		final var result = new BaseRepresentationModel();
		createHateoasLinksForUser(uuid, result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@PutMapping(value = "users/{uuid}/enable")
	@AuditAfter(value = "enableUser", changeSecurity = true)
	public ResponseEntity<BaseRepresentationModel> enableUser(@PathVariable("uuid") @NotEmpty final String _uuid) {
		final var uuid = sanitize(_uuid);
		authenticationService.enableUser(uuid);

		final var result = new BaseRepresentationModel();
		createHateoasLinksForUser(uuid, result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@PutMapping(value = "users/{uuid}/switchresetpassword")
	@AuditAfter(value = "switchUserMustResetPassword", changeSecurity = true)
	public ResponseEntity<BaseRepresentationModel> switchUserMustResetPassword(@PathVariable("uuid") @NotEmpty final String _uuid) {
		final var uuid = sanitize(_uuid);
		authenticationService.setUserMustChangePassword(uuid);

		final var result = new BaseRepresentationModel();
		createHateoasLinksForUser(uuid, result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@PutMapping(value = "users/{uuid}/resetlogontrials")
	@AuditAfter(value = "resetUserLogonTrials", changeSecurity = true)
	public ResponseEntity<BaseRepresentationModel> resetUserLogonTrials(@PathVariable("uuid") @NotEmpty final String _uuid) {
		final var uuid = sanitize(_uuid);
		authenticationService.resetUserLogonTrials(uuid);

		final var result = new BaseRepresentationModel();
		createHateoasLinksForUser(uuid, result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@DeleteMapping(value = "users/{uuid}")
	@AuditAfter(value = "removeUser", changeSecurity = true)
	public ResponseEntity<BaseRepresentationModel> removeUser(@PathVariable("uuid") @NotEmpty final String _uuid) {
		final var uuid = sanitize(_uuid);
		authenticationService.removeUser(uuid);

		final var result = new BaseRepresentationModel();
		createHateoasLinksForUser(uuid, result);
		return new ResponseEntity<>(result, OK);
	}

	////////// Group zone

	@Transactional(readOnly = false)
	@AuditAfter(value = "addGroup", changeSecurity = true)
	@PostMapping(value = "groups")
	public ResponseEntity<BaseRepresentationModel> addGroup(@RequestBody @Validated final AddGroupOrRoleDto newGroup) {
		authenticationService.addGroup(newGroup);
		final var result = new BaseRepresentationModel();
		createHateoasLinksForGroup(newGroup.getName(), result);
		return new ResponseEntity<>(result, CREATED);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "renameGroup", changeSecurity = true)
	@PostMapping(value = "groups/rename")
	public ResponseEntity<BaseRepresentationModel> renameGroup(@RequestBody @Validated final RenameGroupOrRoleDto renameGroup) {
		authenticationService.renameGroup(renameGroup);
		final var result = new BaseRepresentationModel();
		createHateoasLinksForGroup(renameGroup.getNewname(), result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "setGroupDescription", changeSecurity = true)
	@PutMapping(value = "groups/description")
	public ResponseEntity<BaseRepresentationModel> setGroupDescription(@RequestBody @Validated final AddGroupOrRoleDto changeGroup) {
		authenticationService.setGroupDescription(changeGroup);
		final var result = new BaseRepresentationModel();
		createHateoasLinksForGroup(changeGroup.getName(), result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "addUserInGroup", changeSecurity = true)
	@PostMapping(value = "users/{uuid}/ingroup/{name}")
	public ResponseEntity<BaseRepresentationModel> addUserInGroup(@PathVariable("uuid") @NotEmpty final String _userUUID,
	                                                              @PathVariable("name") @NotEmpty final String _groupName) {
		final var userUUID = sanitize(_userUUID);
		final var groupName = sanitize(_groupName);
		authenticationService.addUserInGroup(userUUID, groupName);
		final var result = new BaseRepresentationModel();
		createHateoasLinksForUser(userUUID, result);
		return new ResponseEntity<>(result, CREATED);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "removeUserInGroup", changeSecurity = true)
	@DeleteMapping(value = "users/{uuid}/ingroup/{name}")
	public ResponseEntity<BaseRepresentationModel> removeUserInGroup(@PathVariable("uuid") @NotEmpty final String _userUUID,
	                                                                 @PathVariable("name") @NotEmpty final String _groupName) {
		final var userUUID = sanitize(_userUUID);
		final var groupName = sanitize(_groupName);
		authenticationService.removeUserInGroup(userUUID, groupName);
		final var result = new BaseRepresentationModel();
		createHateoasLinksForUser(userUUID, result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "removeGroup", changeSecurity = true)
	@DeleteMapping(value = "groups/{name}")
	public ResponseEntity<BaseRepresentationModel> removeGroup(@PathVariable("name") @NotEmpty final String _groupName) {
		final var groupName = sanitize(_groupName);
		authenticationService.removeGroup(groupName);
		final var result = new BaseRepresentationModel();
		createHateoasLinksForGroup(groupName, result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "listAllGroups", changeSecurity = false)
	@GetMapping(value = "groups")
	public ResponseEntity<ItemListDto<GroupOrRoleDto>> listAllGroups() {
		final var result = new ItemListDto<>(authenticationService.listAllGroups());
		createHateoasLinksForGroup(HATEOAS_DEFAULT_GROUP_NAME, result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "listGroupsForUser", changeSecurity = false)
	@GetMapping(value = "users/{uuid}/groups")
	public ResponseEntity<ItemListDto<GroupOrRoleDto>> listGroupsForUser(@PathVariable("uuid") @NotEmpty final String _userUUID) {
		final var userUUID = sanitize(_userUUID);
		final var result = new ItemListDto<>(authenticationService.listGroupsForUser(userUUID));
		createHateoasLinksForUser(userUUID, result);
		return new ResponseEntity<>(result, OK);
	}

	////////// Role zone

	@Transactional(readOnly = false)
	@AuditAfter(value = "addRole", changeSecurity = true)
	@PostMapping(value = "roles")
	public ResponseEntity<BaseRepresentationModel> addRole(@RequestBody @Validated final AddGroupOrRoleDto newRole) {
		authenticationService.addRole(newRole);
		final var result = new BaseRepresentationModel();
		createHateoasLinksForRoles(newRole.getName(), result);
		return new ResponseEntity<>(result, CREATED);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "renameRole", changeSecurity = true)
	@PostMapping(value = "roles/rename")
	public ResponseEntity<BaseRepresentationModel> renameRole(@RequestBody @Validated final RenameGroupOrRoleDto renameRole) {
		authenticationService.renameRole(renameRole);
		final var result = new BaseRepresentationModel();
		createHateoasLinksForRoles(renameRole.getName(), result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "setRoleDescription", changeSecurity = true)
	@PutMapping(value = "roles/description")
	public ResponseEntity<BaseRepresentationModel> setRoleDescription(@RequestBody @Validated final AddGroupOrRoleDto changeRole) {
		authenticationService.setRoleDescription(changeRole);
		final var result = new BaseRepresentationModel();
		createHateoasLinksForRoles(changeRole.getName(), result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "setRoleOnlyForClients", changeSecurity = true)
	@PutMapping(value = "roles/{rolename}/setOnlyForClient")
	public ResponseEntity<BaseRepresentationModel> setRoleOnlyForClient(@PathVariable("rolename") @NotEmpty final String _roleName,
	                                                                    @RequestBody @Validated final ChangeIPDto setIp) {
		final var roleName = sanitize(_roleName);
		authenticationService.setRoleOnlyForClient(roleName, setIp.getIp());
		final var result = new BaseRepresentationModel();
		createHateoasLinksForRoles(roleName, result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "addGroupInRole", changeSecurity = true)
	@PostMapping(value = "groups/{groupname}/inrole/{rolename}")
	public ResponseEntity<BaseRepresentationModel> addGroupInRole(@PathVariable("groupname") @NotEmpty final String _groupName,
	                                                              @PathVariable("rolename") @NotEmpty final String _roleName) {
		final var roleName = sanitize(_roleName);
		final var groupName = sanitize(_groupName);
		authenticationService.addGroupInRole(groupName, roleName);
		final var result = new BaseRepresentationModel();
		createHateoasLinksForRoles(roleName, result);
		return new ResponseEntity<>(result, CREATED);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "removeGroupInRole", changeSecurity = true)
	@DeleteMapping(value = "groups/{groupname}/inrole/{rolename}")
	public ResponseEntity<BaseRepresentationModel> removeGroupInRole(@PathVariable("groupname") @NotEmpty final String _groupName,
	                                                                 @PathVariable("rolename") @NotEmpty final String _roleName) {
		final var roleName = sanitize(_roleName);
		final var groupName = sanitize(_groupName);
		authenticationService.removeGroupInRole(groupName, roleName);
		final var result = new BaseRepresentationModel();
		createHateoasLinksForRoles(roleName, result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "removeRole", changeSecurity = true)
	@DeleteMapping(value = "roles/{rolename}")
	public ResponseEntity<BaseRepresentationModel> removeRole(@PathVariable("rolename") @NotEmpty final String _roleName) {
		final var roleName = sanitize(_roleName);
		authenticationService.removeRole(roleName);
		final var result = new BaseRepresentationModel();
		createHateoasLinksForRoles(roleName, result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "listAllRoles", changeSecurity = false)
	@GetMapping(value = "roles")
	public ResponseEntity<ItemListDto<GroupOrRoleDto>> listAllRoles() {
		final var result = new ItemListDto<>(authenticationService.listAllRoles());
		createHateoasLinksForRoles("role-name", result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "listRolesForGroup", changeSecurity = false)
	@GetMapping(value = "groups/{groupname}/roles")
	public ResponseEntity<ItemListDto<GroupOrRoleDto>> listRolesForGroup(@PathVariable("groupname") @NotEmpty final String _groupName) {
		final var groupName = sanitize(_groupName);
		final var result = new ItemListDto<>(authenticationService.listRolesForGroup(groupName));
		createHateoasLinksForGroup(groupName, result);
		return new ResponseEntity<>(result, OK);
	}

	////////// Rights zone

	@Transactional(readOnly = false)
	@AuditAfter(value = "addRightInRole", changeSecurity = true)
	@PostMapping(value = "roles/{rolename}/rights/{rightname}")
	public ResponseEntity<BaseRepresentationModel> addRightInRole(@PathVariable("rolename") @NotEmpty final String _roleName,
	                                                              @PathVariable("rightname") @NotEmpty final String rightName) {
		final var roleName = sanitize(_roleName);
		authenticationService.addRightInRole(roleName, rightName);
		final var result = new BaseRepresentationModel();
		createHateoasLinksForRights(roleName, rightName, result);
		return new ResponseEntity<>(result, CREATED);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "removeRightInRole", changeSecurity = true)
	@DeleteMapping(value = "roles/{rolename}/rights/{rightname}")
	public ResponseEntity<BaseRepresentationModel> removeRightInRole(@PathVariable("rolename") @NotEmpty final String _roleName,
	                                                                 @PathVariable("rightname") @NotEmpty final String rightName) {
		final var roleName = sanitize(_roleName);
		authenticationService.removeRightInRole(roleName, rightName);
		final var result = new BaseRepresentationModel();
		createHateoasLinksForRights(roleName, rightName, result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "getAllRights", changeSecurity = false)
	@GetMapping(value = "rights")
	public ResponseEntity<ItemListDto<String>> getAllRights() {
		final var result = new ItemListDto<>(authenticationService.getAllRights());
		createHateoasLinksForRights("role-name", "right-name", result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "listRightsForRole", changeSecurity = false)
	@GetMapping(value = "roles/{rolename}/rights")
	public ResponseEntity<ItemListDto<String>> listRightsForRole(@PathVariable("rolename") @NotEmpty final String _roleName) {
		final var roleName = sanitize(_roleName);
		final var result = new ItemListDto<>(authenticationService.listRightsForRole(roleName));
		createHateoasLinksForRights(roleName, "right-name", result);
		return new ResponseEntity<>(result, OK);
	}

	////////// Contexts right zone

	@Transactional(readOnly = false)
	@AuditAfter(value = "addContextInRight", changeSecurity = true)
	@PostMapping(value = "roles/{rolename}/rights/{rightname}/contexts/{context}")
	public ResponseEntity<BaseRepresentationModel> addContextInRight(@PathVariable("rolename") @NotEmpty final String _roleName,
	                                                                 @PathVariable("rightname") @NotEmpty final String rightName,
	                                                                 @PathVariable("context") @NotEmpty final String context) {
		final var roleName = sanitize(_roleName);
		authenticationService.addContextInRight(roleName, rightName, context);
		final var result = new BaseRepresentationModel();
		createHateoasLinksForContextsRights(roleName, rightName, context, result);
		return new ResponseEntity<>(result, CREATED);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "removeContextInRight", changeSecurity = true)
	@DeleteMapping(value = "roles/{rolename}/rights/{rightname}/contexts/{context}")
	public ResponseEntity<BaseRepresentationModel> removeContextInRight(@PathVariable("rolename") @NotEmpty final String _roleName,
	                                                                    @PathVariable("rightname") @NotEmpty final String rightName,
	                                                                    @PathVariable("context") @NotEmpty final String context) {
		final var roleName = sanitize(_roleName);
		authenticationService.removeContextInRight(roleName, rightName, context);
		final var result = new BaseRepresentationModel();
		createHateoasLinksForContextsRights(roleName, rightName, context, result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "listContextsForRight", changeSecurity = false)
	@GetMapping(value = "roles/{rolename}/rights/{rightname}/contexts")
	public ResponseEntity<ItemListDto<String>> listContextsForRight(@PathVariable("rolename") @NotEmpty final String _roleName,
	                                                                @PathVariable("rightname") @NotEmpty final String rightName) {
		final var roleName = sanitize(_roleName);
		final var result = new ItemListDto<>(authenticationService.listContextsForRight(roleName, rightName));
		createHateoasLinksForContextsRights(roleName, rightName, "context-name", result);
		return new ResponseEntity<>(result, OK);
	}

	////////// Reverse searchs

	@Transactional(readOnly = false)
	@AuditAfter(value = "listLinkedUsersForGroup", changeSecurity = false)
	@GetMapping(value = "groups/{name}/users")
	public ResponseEntity<ItemListDto<UserDto>> listLinkedUsersForGroup(@PathVariable("name") @NotEmpty final String _groupName) {
		final var groupName = sanitize(_groupName);
		final var result = new ItemListDto<>(authenticationService.listLinkedUsersForGroup(groupName));
		createHateoasLinksForGroup(groupName, result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@AuditAfter(value = "listLinkedGroupsForRole", changeSecurity = false)
	@GetMapping(value = "roles/{name}/groups")
	public ResponseEntity<ItemListDto<GroupOrRoleDto>> listLinkedGroupsForRole(@PathVariable("name") @NotEmpty final String _roleName) {
		final var roleName = sanitize(_roleName);
		final var result = new ItemListDto<>(authenticationService.listLinkedGroupsForRole(roleName));
		createHateoasLinksForRoles(roleName, result);
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
		createHateoasLinksForUser(uuid, result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = true)
	@GetMapping(value = "users/privacy")
	@AuditAfter(value = "getUsersPrivacy", changeSecurity = false)
	public ResponseEntity<ItemListDto<UserPrivacyDto>> getUsersPrivacy(@RequestBody @Validated final ListStringDto userUUIDList) {
		final var list = authenticationService.getUserPrivacyList(userUUIDList.getList());
		final var result = new ItemListDto<>(list);
		createHateoasLinksForUser("<uuid>", result);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@PutMapping(value = "users/{uuid}/privacy")
	@AuditAfter(value = "setUserPrivacy", changeSecurity = true)
	public ResponseEntity<BaseRepresentationModel> setUserPrivacy(@RequestBody @Validated final UserPrivacyDto userPrivacyDto,
	                                                              @PathVariable("uuid") @NotEmpty final String _userUUID) {
		final var userUUID = sanitize(_userUUID);
		authenticationService.setUserPrivacy(userUUID, userPrivacyDto);
		final var result = new BaseRepresentationModel();
		createHateoasLinksForUser(userUUID, result);
		return new ResponseEntity<>(result, OK);
	}

	/**
	 * prepareHateoasLink
	 */
	private void prepHLink(final BaseRepresentationModel ressource,
	                       final Function<RestControllerUser, Object> linkTo,
	                       final String rel,
	                       final RequestMethod method) {
		final var c = RestControllerUser.class;
		final var link = linkTo.apply(methodOn(c));
		ressource.add(new WsDtoLink(linkTo(link).withRel(rel), method));
	}

	private void createHateoasLinksForUser(final String userUUID, final BaseRepresentationModel res) {
		prepHLink(res, c -> c.addUser(new AddUserDto()), "add", POST);
		prepHLink(res, c -> c.listUsers(0, dbMaxFetchSize), "list", GET);
		prepHLink(res, c -> c.getUser(userUUID), "show", GET);
		prepHLink(res, c -> c.disableUser(userUUID), "disable", PUT);
		prepHLink(res, c -> c.enableUser(userUUID), "enable", PUT);
		prepHLink(res, c -> c.switchUserMustResetPassword(userUUID), "switchresetpassword", PUT);
		prepHLink(res, c -> c.resetUserLogonTrials(userUUID), "resetlogontrials", PUT);
		prepHLink(res, c -> c.removeUser(userUUID), HATEOAS_REMOVE, DELETE);
		prepHLink(res, c -> c.listGroupsForUser(userUUID), "list-group", GET);
		prepHLink(res, c -> c.addUserInGroup(userUUID, HATEOAS_DEFAULT_GROUP_NAME), "add-user-in-group", POST);
		prepHLink(res, c -> c.removeUserInGroup("user-uuid", HATEOAS_DEFAULT_GROUP_NAME),
		        "remove-user-in-group", DELETE);
		prepHLink(res, c -> c.getUserPrivacy(userUUID), "get-user-privacy", GET);
		prepHLink(res, c -> c.getUsersPrivacy(new ListStringDto()), "get-users-privacy", GET);
		prepHLink(res, c -> c.setUserPrivacy(new UserPrivacyDto(), userUUID), "set-user-privacy", PUT);
	}

	private void createHateoasLinksForGroup(final String groupName, final BaseRepresentationModel res) {
		prepHLink(res, c -> c.addGroup(new AddGroupOrRoleDto()), "add", POST);
		prepHLink(res, RestControllerUser::listAllGroups, "list", GET);
		prepHLink(res, c -> c.renameGroup(new RenameGroupOrRoleDto()), "rename", POST);
		prepHLink(res, c -> c.setGroupDescription(new AddGroupOrRoleDto()), "set-description", PUT);
		prepHLink(res, c -> c.removeGroup(groupName), HATEOAS_REMOVE, DELETE);
		prepHLink(res, c -> c.listLinkedUsersForGroup(groupName), "list-users-by-group", GET);
		prepHLink(res, c -> c.listRolesForGroup(groupName), "list-roles-for-group", GET);
	}

	private void createHateoasLinksForRoles(final String roleName, final BaseRepresentationModel res) {
		prepHLink(res, c -> c.addRole(new AddGroupOrRoleDto()), "add", POST);
		prepHLink(res, RestControllerUser::listAllRoles, "list", GET);
		prepHLink(res, c -> c.renameRole(new RenameGroupOrRoleDto()), "rename", POST);
		prepHLink(res, c -> c.setRoleDescription(new AddGroupOrRoleDto()), "set-description", PUT);
		prepHLink(res, c -> c.setRoleOnlyForClient(roleName, new ChangeIPDto()), "set-only-for-clients", PUT);
		prepHLink(res, c -> c.addGroupInRole(HATEOAS_DEFAULT_GROUP_NAME, roleName), "add-group-in-role", POST);
		prepHLink(res, c -> c.removeRole(roleName), HATEOAS_REMOVE, DELETE);
		prepHLink(res, c -> c.listLinkedGroupsForRole(roleName), "list-groups-by-role", GET);
		prepHLink(res, c -> c.removeGroupInRole(HATEOAS_DEFAULT_GROUP_NAME, roleName), "remove-group-in-role", DELETE);
	}

	private void createHateoasLinksForRights(final String roleName,
	                                         final String rightName,
	                                         final BaseRepresentationModel res) {
		prepHLink(res, c -> c.addRightInRole(roleName, rightName), "add", POST);
		prepHLink(res, RestControllerUser::getAllRights, "list", GET);
		prepHLink(res, c -> c.listRightsForRole(roleName), "list-rights", GET);
		prepHLink(res, c -> c.removeRightInRole(roleName, rightName), HATEOAS_REMOVE, DELETE);
	}

	private void createHateoasLinksForContextsRights(final String roleName,
	                                                 final String rightName,
	                                                 final String context,
	                                                 final BaseRepresentationModel res) {
		prepHLink(res, c -> c.addContextInRight(roleName, rightName, context), "add", POST);
		prepHLink(res, c -> c.listContextsForRight(roleName, rightName), "list", GET);
		prepHLink(res, c -> c.removeContextInRight(roleName, rightName, context), HATEOAS_REMOVE, DELETE);
	}

}
