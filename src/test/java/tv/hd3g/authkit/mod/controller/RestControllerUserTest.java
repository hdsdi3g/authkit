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

import static java.util.stream.Collectors.toUnmodifiableList;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_UTF8;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomThing;
import static tv.hd3g.authkit.tool.DataGenerator.makeUUID;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserLogin;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserPassword;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.web.bind.annotation.RequestMapping;

import com.fasterxml.jackson.databind.ObjectMapper;

import tv.hd3g.authkit.mod.component.EndpointsListener;
import tv.hd3g.authkit.mod.dto.Password;
import tv.hd3g.authkit.mod.dto.ressource.UserPrivacyDto;
import tv.hd3g.authkit.mod.dto.validated.AddGroupOrRoleDto;
import tv.hd3g.authkit.mod.dto.validated.AddUserDto;
import tv.hd3g.authkit.mod.dto.validated.ChangeIPDto;
import tv.hd3g.authkit.mod.dto.validated.ListStringDto;
import tv.hd3g.authkit.mod.dto.validated.LoginFormDto;
import tv.hd3g.authkit.mod.dto.validated.RenameGroupOrRoleDto;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.BadPasswordUserCantLoginException;
import tv.hd3g.authkit.mod.repository.CredentialRepository;
import tv.hd3g.authkit.mod.repository.UserDao;
import tv.hd3g.authkit.mod.repository.UserRepository;
import tv.hd3g.authkit.mod.service.AuthenticationService;
import tv.hd3g.authkit.mod.service.SecuredTokenService;
import tv.hd3g.authkit.tool.AddUserTestDto;
import tv.hd3g.authkit.tool.DataGenerator;

@SpringBootTest
@AutoConfigureMockMvc
public class RestControllerUserTest {

	private static final String baseMapping = RestControllerUser.class.getAnnotation(RequestMapping.class).value()[0];

	@Autowired
	private MockMvc mvc;
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private AuthenticationService authenticationService;
	@Autowired
	private SecuredTokenService securedTokenService;
	@Autowired
	private EndpointsListener endpointsListener;
	@Autowired
	private UserDao userDao;
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private CredentialRepository credentialRepository;
	@Value("${authkit.realm}")
	private String realm;
	@Value("${authkit.dbMaxFetchSize:50}")
	private int dbMaxFetchSize;

	private HttpHeaders baseHeaders;

	private static final ResultMatcher statusCreated = status().isCreated();
	private static final ResultMatcher statusOk = status().isOk();
	private static final ResultMatcher statusPartial = status().isPartialContent();
	private static final ResultMatcher contentTypeJsonUtf8 = content().contentType(APPLICATION_JSON_UTF8);
	private static final ResultMatcher statusOkUtf8Hateoas = ResultMatcher.matchAll(
	        statusOk, contentTypeJsonUtf8, checkHateoasPresence());

	@BeforeEach
	private void init() {
		final var authToken = securedTokenService.loggedUserRightsGenerateToken(
		        makeUUID(), Duration.ofDays(1), endpointsListener.getAllRights(), null);
		baseHeaders = new HttpHeaders();
		baseHeaders.set(AUTHORIZATION, "bearer " + authToken);
		baseHeaders.setAccept(Arrays.asList(APPLICATION_JSON_UTF8));
	}

	private static ResultMatcher checkHateoasPresence() {
		final var linkPresence = jsonPath("$.links").isArray();
		return ResultMatcher.matchAll(linkPresence);
	}

	@Nested
	class User {
		@Test
		public void addUser() throws Exception {
			final var addUser = new AddUserTestDto();

			mvc.perform(post(baseMapping + "/" + "users")
			        .headers(baseHeaders)
			        .contentType(APPLICATION_JSON_UTF8)
			        .content(objectMapper.writeValueAsString(addUser)))
			        .andExpect(statusCreated)
			        .andExpect(contentTypeJsonUtf8)
			        .andExpect(jsonPath("$.userName", is(addUser.getUserLogin())))
			        .andExpect(jsonPath("$.uuid").isString())
			        .andExpect(jsonPath("$.realm", is(realm)))
			        .andExpect(checkHateoasPresence());
		}

		@Test
		public void getUser() throws Exception {
			final var addUser = new AddUserTestDto();
			final var uuid = authenticationService.addUser(addUser.makeClassicDto());

			mvc.perform(get(baseMapping + "/" + "users" + "/" + uuid)
			        .headers(baseHeaders))
			        .andExpect(statusOk)
			        .andExpect(contentTypeJsonUtf8)
			        .andExpect(jsonPath("$.created").exists())
			        .andExpect(jsonPath("$.uuid", is(uuid)))
			        .andExpect(jsonPath("$.login", is(addUser.getUserLogin())))
			        .andExpect(jsonPath("$.realm", is(realm)))
			        .andExpect(jsonPath("$.enabled", is(true)))
			        .andExpect(jsonPath("$.totpEnabled", is(false)))
			        .andExpect(jsonPath("$.mustChangePassword", is(false)))
			        .andExpect(checkHateoasPresence());
		}

		@Test
		public void listUserSimple() throws Exception {
			assertHasSomeUsersInDb();
			final var response = mvc.perform(get(baseMapping + "/" + "users")
			        .headers(baseHeaders))
			        .andExpect(statusPartial)
			        .andExpect(contentTypeJsonUtf8)
			        .andExpect(jsonPath("$.items").isArray())
			        .andExpect(jsonPath("$.items.length()", is(dbMaxFetchSize)))
			        .andExpect(checkHateoasPresence())
			        .andReturn().getResponse();

			final int finalCount = (int) userRepository.count();
			assertEquals("user " + dbMaxFetchSize, response.getHeader("Accept-Range"));
			assertEquals("0-" + dbMaxFetchSize + "/" + finalCount, response.getHeader("Content-Range"));
		}

		@Test
		public void listUserRange() throws Exception {
			assertHasSomeUsersInDb();
			final var response = mvc.perform(get(baseMapping + "/" + "users?pos=1&size=5")
			        .headers(baseHeaders))
			        .andExpect(statusPartial)
			        .andExpect(contentTypeJsonUtf8)
			        .andExpect(jsonPath("$.items").isArray())
			        .andExpect(jsonPath("$.items.length()", is(5)))
			        .andExpect(checkHateoasPresence())
			        .andReturn().getResponse();

			final int finalCount = (int) userRepository.count();
			assertEquals("user " + dbMaxFetchSize, response.getHeader("Accept-Range"));
			assertEquals("1-5/" + finalCount, response.getHeader("Content-Range"));
		}

		@Test
		public void disableUser() throws Exception {
			final var userUUID = authenticationService.addUser(new AddUserTestDto().makeClassicDto());

			mvc.perform(put(baseMapping + "/users/" + userUUID + "/disable")
			        .headers(baseHeaders))
			        .andExpect(statusOk)
			        .andExpect(contentTypeJsonUtf8)
			        .andExpect(checkHateoasPresence());

			final var user = userDao.getUserByUUID(UUID.fromString(userUUID)).get();
			assertFalse(user.isEnabled());
		}

		@Test
		public void enableUser() throws Exception {
			final var userUUID = authenticationService.addUser(new AddUserTestDto().makeClassicDto());
			authenticationService.disableUser(userUUID);

			mvc.perform(put(baseMapping + "/users/" + userUUID + "/enable")
			        .headers(baseHeaders))
			        .andExpect(ResultMatcher.matchAll(statusOk, contentTypeJsonUtf8, checkHateoasPresence()));

			final var user = userDao.getUserByUUID(UUID.fromString(userUUID)).get();
			assertTrue(user.isEnabled());
		}

		@Test
		public void switchUserMustResetPassword() throws Exception {
			final var userUUID = authenticationService.addUser(new AddUserTestDto().makeClassicDto());

			mvc.perform(put(baseMapping + "/users/" + userUUID + "/switchresetpassword")
			        .headers(baseHeaders))
			        .andExpect(statusOk)
			        .andExpect(contentTypeJsonUtf8)
			        .andExpect(checkHateoasPresence());

			final var user = userDao.getUserByUUID(UUID.fromString(userUUID)).get();
			assertTrue(user.isMustChangePassword());
		}

		@Test
		public void resetUserLogonTrials() throws Exception {
			final var addUser = new AddUserTestDto();
			final var userUUID = authenticationService.addUser(addUser.makeClassicDto());

			final var loginFormFail = new LoginFormDto();
			loginFormFail.setUserlogin(addUser.getUserLogin());
			loginFormFail.setUserpassword(new Password(makeUserPassword()));
			final var request = Mockito.mock(HttpServletRequest.class);
			DataGenerator.setupMock(request);
			assertThrows(BadPasswordUserCantLoginException.class, () -> {
				authenticationService.userLoginRequest(request, loginFormFail);
			});
			assertEquals(1, credentialRepository.getByUserUUID(userUUID).getLogontrial());

			mvc.perform(put(baseMapping + "/users/" + userUUID + "/resetlogontrials")
			        .headers(baseHeaders))
			        .andExpect(statusOk)
			        .andExpect(contentTypeJsonUtf8)
			        .andExpect(checkHateoasPresence());

			assertEquals(0, credentialRepository.getByUserUUID(userUUID).getLogontrial());
		}

		@Test
		public void removeUser() throws Exception {
			final var userUUID = authenticationService.addUser(new AddUserTestDto().makeClassicDto());

			mvc.perform(delete(baseMapping + "/users/" + userUUID)
			        .headers(baseHeaders))
			        .andExpect(statusOk)
			        .andExpect(contentTypeJsonUtf8)
			        .andExpect(checkHateoasPresence());

			final var userPresence = userDao.getUserByUUID(UUID.fromString(userUUID)).isPresent();
			assertFalse(userPresence);
		}

		private void assertHasSomeUsersInDb() {
			final int initialCount = (int) userRepository.count();
			if (initialCount < dbMaxFetchSize + 1) {
				IntStream.range(0, dbMaxFetchSize + 1).forEach(i -> {
					authenticationService.addUser(new AddUserTestDto().makeClassicDto());
				});
			}
		}
	}

	@Nested
	class Group {
		@Test
		public void addGroup() throws Exception {
			final var addGroup = new AddGroupOrRoleDto();
			addGroup.setName(makeUserLogin());
			addGroup.setDescription(makeRandomThing());

			mvc.perform(post(baseMapping + "/" + "groups")
			        .headers(baseHeaders)
			        .contentType(APPLICATION_JSON_UTF8)
			        .content(objectMapper.writeValueAsString(addGroup)))
			        .andExpect(statusCreated)
			        .andExpect(contentTypeJsonUtf8)
			        .andExpect(checkHateoasPresence());
		}

		@Test
		public void renameGroup() throws Exception {
			final AddGroupOrRoleDto g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);

			final var rename = new RenameGroupOrRoleDto();
			rename.setName(g.getName());
			rename.setNewname(makeUserLogin());

			mvc.perform(post(baseMapping + "/" + "groups/rename")
			        .headers(baseHeaders)
			        .contentType(APPLICATION_JSON_UTF8)
			        .content(objectMapper.writeValueAsString(rename)))
			        .andExpect(statusOkUtf8Hateoas);
		}

		@Test
		public void setGroupDescription() throws Exception {
			final AddGroupOrRoleDto g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			g.setDescription(makeRandomThing());
			authenticationService.addGroup(g);

			final var change = new AddGroupOrRoleDto();
			change.setName(g.getName());
			change.setDescription(makeRandomThing());

			mvc.perform(put(baseMapping + "/" + "groups/description")
			        .headers(baseHeaders)
			        .contentType(APPLICATION_JSON_UTF8)
			        .content(objectMapper.writeValueAsString(change)))
			        .andExpect(statusOkUtf8Hateoas);
		}

		@Test
		public void addUserInGroup() throws Exception {
			final var addUser = new AddUserDto();
			addUser.setUserLogin(makeUserLogin());
			addUser.setUserPassword(new Password(makeUserPassword()));

			final var uuid = authenticationService.addUser(addUser);
			final AddGroupOrRoleDto g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);

			mvc.perform(post(baseMapping + "/" + "users/" + uuid + "/ingroup/" + g.getName())
			        .headers(baseHeaders))
			        .andExpect(statusCreated)
			        .andExpect(contentTypeJsonUtf8)
			        .andExpect(checkHateoasPresence());
		}

		@Test
		public void removeUserInGroup() throws Exception {
			final var addUser = new AddUserDto();
			addUser.setUserLogin(makeUserLogin());
			addUser.setUserPassword(new Password(makeUserPassword()));

			final var uuid = authenticationService.addUser(addUser);
			final AddGroupOrRoleDto g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			authenticationService.addUserInGroup(uuid, g.getName());

			mvc.perform(delete(baseMapping + "/" + "users/" + uuid + "/ingroup/" + g.getName())
			        .headers(baseHeaders))
			        .andExpect(statusOkUtf8Hateoas);
		}

		@Test
		public void removeGroup() throws Exception {
			final AddGroupOrRoleDto g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);

			mvc.perform(delete(baseMapping + "/" + "groups/" + g.getName())
			        .headers(baseHeaders))
			        .andExpect(statusOkUtf8Hateoas);
		}

		@Test
		public void listAllGroups() throws Exception {
			final AddGroupOrRoleDto g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);

			mvc.perform(get(baseMapping + "/" + "groups")
			        .headers(baseHeaders))
			        .andExpect(jsonPath("$.items").isArray())
			        .andExpect(statusOkUtf8Hateoas);
		}

		@Test
		public void listGroupsForUser() throws Exception {
			final var addUser = new AddUserDto();
			addUser.setUserLogin(makeUserLogin());
			addUser.setUserPassword(new Password(makeUserPassword()));
			final var uuid = authenticationService.addUser(addUser);
			final AddGroupOrRoleDto g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			authenticationService.addUserInGroup(uuid, g.getName());

			mvc.perform(get(baseMapping + "/" + "users/" + uuid + "/groups")
			        .headers(baseHeaders))
			        .andExpect(jsonPath("$.items").isArray())
			        .andExpect(jsonPath("$.items.length()", is(1)))
			        .andExpect(statusOkUtf8Hateoas);
		}

	}

	@Nested
	class Role {
		@Test
		public void addRole() throws Exception {
			final var addRole = new AddGroupOrRoleDto();
			addRole.setName(makeUserLogin());
			addRole.setDescription(makeRandomThing());

			mvc.perform(post(baseMapping + "/" + "roles")
			        .headers(baseHeaders)
			        .contentType(APPLICATION_JSON_UTF8)
			        .content(objectMapper.writeValueAsString(addRole)))
			        .andExpect(statusCreated)
			        .andExpect(contentTypeJsonUtf8)
			        .andExpect(checkHateoasPresence());
		}

		@Test
		public void renameRole() throws Exception {
			final AddGroupOrRoleDto r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);

			final var rename = new RenameGroupOrRoleDto();
			rename.setName(r.getName());
			rename.setNewname(makeUserLogin());

			mvc.perform(post(baseMapping + "/" + "roles/rename")
			        .headers(baseHeaders)
			        .contentType(APPLICATION_JSON_UTF8)
			        .content(objectMapper.writeValueAsString(rename)))
			        .andExpect(statusOkUtf8Hateoas);
		}

		@Test
		public void setRoleDescription() throws Exception {
			final AddGroupOrRoleDto r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			r.setDescription(makeRandomThing());
			authenticationService.addRole(r);

			final var change = new AddGroupOrRoleDto();
			change.setName(r.getName());
			change.setDescription(makeRandomThing());

			mvc.perform(put(baseMapping + "/" + "roles/description")
			        .headers(baseHeaders)
			        .contentType(APPLICATION_JSON_UTF8)
			        .content(objectMapper.writeValueAsString(change)))
			        .andExpect(statusOkUtf8Hateoas);
		}

		@Test
		public void setRoleOnlyForClient() throws Exception {
			final AddGroupOrRoleDto r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);

			final var ip = DataGenerator.makeRandomIPv4().getHostAddress();
			final var change = new ChangeIPDto();
			change.setIp(ip);

			mvc.perform(put(baseMapping + "/" + "roles/" + r.getName() + "/setOnlyForClient")
			        .headers(baseHeaders)
			        .contentType(APPLICATION_JSON_UTF8)
			        .content(objectMapper.writeValueAsString(change)))
			        .andExpect(statusOkUtf8Hateoas);
		}

		@Test
		public void addGroupInRole() throws Exception {
			final AddGroupOrRoleDto g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			final AddGroupOrRoleDto r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);

			mvc.perform(post(baseMapping + "/" + "groups/" + g.getName() + "/inrole/" + r.getName())
			        .headers(baseHeaders))
			        .andExpect(statusCreated)
			        .andExpect(contentTypeJsonUtf8)
			        .andExpect(checkHateoasPresence());
		}

		@Test
		public void removeGroupInRole() throws Exception {
			final AddGroupOrRoleDto g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			final AddGroupOrRoleDto r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);

			authenticationService.addGroupInRole(g.getName(), r.getName());

			mvc.perform(delete(baseMapping + "/" + "groups/" + g.getName() + "/inrole/" + r.getName())
			        .headers(baseHeaders))
			        .andExpect(statusOkUtf8Hateoas);
		}

		@Test
		public void removeRole() throws Exception {
			final AddGroupOrRoleDto r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);

			mvc.perform(delete(baseMapping + "/" + "roles/" + r.getName())
			        .headers(baseHeaders))
			        .andExpect(statusOkUtf8Hateoas);
		}

		@Test
		public void listAllRoles() throws Exception {
			final AddGroupOrRoleDto r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);

			mvc.perform(get(baseMapping + "/" + "roles")
			        .headers(baseHeaders))
			        .andExpect(jsonPath("$.items").isArray())
			        .andExpect(statusOkUtf8Hateoas);
		}

		@Test
		public void listRolesForGroup() throws Exception {
			final AddGroupOrRoleDto g = new AddGroupOrRoleDto();
			g.setName("test:" + makeUserLogin());
			authenticationService.addGroup(g);
			final AddGroupOrRoleDto r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			authenticationService.addGroupInRole(g.getName(), r.getName());

			mvc.perform(get(baseMapping + "/" + "groups/" + g.getName() + "/roles")
			        .headers(baseHeaders))
			        .andExpect(jsonPath("$.items").isArray())
			        .andExpect(jsonPath("$.items.length()", is(1)))
			        .andExpect(statusOkUtf8Hateoas);
		}

	}

	@Nested
	class Rights {

		@Test
		public void addRightInRole() throws Exception {
			final AddGroupOrRoleDto r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			final var rightName = makeUserLogin();

			mvc.perform(post(baseMapping + "/" + "roles/" + r.getName() + "/rights/" + rightName)
			        .headers(baseHeaders))
			        .andExpect(statusCreated)
			        .andExpect(contentTypeJsonUtf8)
			        .andExpect(checkHateoasPresence());
		}

		@Test
		public void removeRightInRole() throws Exception {
			final AddGroupOrRoleDto r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			final var rightName = makeUserLogin();
			authenticationService.addRightInRole(r.getName(), rightName);

			mvc.perform(delete(baseMapping + "/" + "roles/" + r.getName() + "/rights/" + rightName)
			        .headers(baseHeaders))
			        .andExpect(statusOkUtf8Hateoas);
		}

		@Test
		public void getAllRights() throws Exception {
			mvc.perform(get(baseMapping + "/" + "rights")
			        .headers(baseHeaders))
			        .andExpect(jsonPath("$.items").isArray())
			        .andExpect(statusOkUtf8Hateoas);
		}

		@Test
		public void listRightsForRole() throws Exception {
			final AddGroupOrRoleDto r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			final var rightName = makeUserLogin();
			authenticationService.addRightInRole(r.getName(), rightName);

			mvc.perform(get(baseMapping + "/" + "roles/" + r.getName() + "/rights")
			        .headers(baseHeaders))
			        .andExpect(jsonPath("$.items").isArray())
			        .andExpect(jsonPath("$.items.length()", is(1)))
			        .andExpect(statusOkUtf8Hateoas);
		}

		@Test
		public void listContextsForRight() throws Exception {
			final AddGroupOrRoleDto r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			final var rightName = makeUserLogin();
			authenticationService.addRightInRole(r.getName(), rightName);
			final var context = makeUserLogin();
			authenticationService.addContextInRight(r.getName(), rightName, context);

			mvc.perform(get(baseMapping + "/" + "roles/" + r.getName() + "/rights/" + rightName + "/contexts")
			        .headers(baseHeaders))
			        .andExpect(jsonPath("$.items").isArray())
			        .andExpect(jsonPath("$.items.length()", is(1)))
			        .andExpect(statusOkUtf8Hateoas);
		}

		@Test
		public void addContextInRight() throws Exception {
			final AddGroupOrRoleDto r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			final var rightName = makeUserLogin();
			authenticationService.addRightInRole(r.getName(), rightName);
			final var context = makeUserLogin();

			mvc.perform(post(baseMapping + "/" + "roles/" + r.getName() + "/rights/" + rightName + "/contexts/"
			                 + context)
			                         .headers(baseHeaders))
			        .andExpect(statusCreated)
			        .andExpect(contentTypeJsonUtf8)
			        .andExpect(checkHateoasPresence());
		}

		@Test
		public void removeContextInRight() throws Exception {
			final AddGroupOrRoleDto r = new AddGroupOrRoleDto();
			r.setName("test:" + makeUserLogin());
			authenticationService.addRole(r);
			final var rightName = makeUserLogin();
			authenticationService.addRightInRole(r.getName(), rightName);
			final var context = makeUserLogin();
			authenticationService.addContextInRight(r.getName(), rightName, context);

			mvc.perform(delete(baseMapping + "/" + "roles/" + r.getName() + "/rights/" + rightName + "/contexts/"
			                   + context)
			                           .headers(baseHeaders))
			        .andExpect(statusOkUtf8Hateoas);
		}
	}

	@Test
	public void listLinkedUsersForGroup() throws Exception {
		final var addUser = new AddUserDto();
		addUser.setUserLogin(makeUserLogin());
		addUser.setUserPassword(new Password(makeUserPassword()));
		final var uuid = authenticationService.addUser(addUser);
		final AddGroupOrRoleDto g = new AddGroupOrRoleDto();
		g.setName("test:" + makeUserLogin());
		authenticationService.addGroup(g);
		authenticationService.addUserInGroup(uuid, g.getName());

		mvc.perform(get(baseMapping + "/" + "groups/" + g.getName() + "/users")
		        .headers(baseHeaders))
		        .andExpect(jsonPath("$.items").isArray())
		        .andExpect(jsonPath("$.items.length()", is(1)))
		        .andExpect(statusOkUtf8Hateoas);
	}

	@Test
	public void listLinkedGroupsForRole() throws Exception {
		final AddGroupOrRoleDto g = new AddGroupOrRoleDto();
		g.setName("test:" + makeUserLogin());
		authenticationService.addGroup(g);
		final AddGroupOrRoleDto r = new AddGroupOrRoleDto();
		r.setName("test:" + makeUserLogin());
		authenticationService.addRole(r);
		authenticationService.addGroupInRole(g.getName(), r.getName());

		mvc.perform(get(baseMapping + "/" + "roles/" + r.getName() + "/groups")
		        .headers(baseHeaders))
		        .andExpect(jsonPath("$.items").isArray())
		        .andExpect(jsonPath("$.items.length()", is(1)))
		        .andExpect(statusOkUtf8Hateoas);
	}

	@Nested
	class UserPrivacy {

		List<String> uuidList;
		Map<String, UserPrivacyDto> expectedItems;

		@BeforeEach
		public void init() {
			uuidList = IntStream.range(0, 10).mapToObj(i -> makeUUID()).collect(toUnmodifiableList());

			expectedItems = uuidList.stream().collect(Collectors.toUnmodifiableMap(u -> u, u -> {
				final var userPrivacyDto = new UserPrivacyDto();
				userPrivacyDto.setAddress(makeUserLogin());
				userPrivacyDto.setCompany(makeUserLogin());
				userPrivacyDto.setCountry(Locale.getDefault().getISO3Country());
				userPrivacyDto.setLang(Locale.getDefault().getISO3Language());
				userPrivacyDto.setEmail(makeUserLogin());
				userPrivacyDto.setName(makeRandomThing());
				userPrivacyDto.setPhone(makeUserLogin());
				userPrivacyDto.setPostalcode(StringUtils.abbreviate(makeUserLogin(), 16));
				return userPrivacyDto;
			}));

			uuidList.forEach(uuid -> authenticationService.setUserPrivacy(uuid, expectedItems.get(uuid)));
		}

		@Test
		public void getUserPrivacy() throws Exception {
			final var uuid = uuidList.get(0);
			final var expected = authenticationService.getUserPrivacyList(List.of(uuid)).get(0);

			mvc.perform(get(baseMapping + "/" + "users/" + uuid + "/privacy")
			        .headers(baseHeaders))
			        .andExpect(jsonPath("$.address").value(expected.getAddress()))
			        .andExpect(jsonPath("$.company").value(expected.getCompany()))
			        .andExpect(jsonPath("$.country").value(expected.getCountry()))
			        .andExpect(jsonPath("$.email").value(expected.getEmail()))
			        .andExpect(jsonPath("$.lang").value(expected.getLang()))
			        .andExpect(jsonPath("$.name").value(expected.getName()))
			        .andExpect(jsonPath("$.phone").value(expected.getPhone()))
			        .andExpect(jsonPath("$.postalcode").value(expected.getPostalcode()))
			        .andExpect(jsonPath("$.userUUID").value(expected.getUserUUID()))
			        .andExpect(statusOkUtf8Hateoas);
		}

		@Test
		public void getUsersPrivacy() throws Exception {
			final ListStringDto userUUIDList = new ListStringDto();
			userUUIDList.setList(uuidList);

			mvc.perform(get(baseMapping + "/" + "users/privacy")
			        .headers(baseHeaders)
			        .contentType(APPLICATION_JSON_UTF8)
			        .content(objectMapper.writeValueAsString(userUUIDList)))
			        .andExpect(jsonPath("$.items").isArray())
			        .andExpect(jsonPath("$.items.length()", is(uuidList.size())))
			        .andExpect(statusOkUtf8Hateoas);
		}

		@Test
		public void setUserPrivacy() throws Exception {
			final var uuid = uuidList.get(0);
			final var expected = authenticationService.getUserPrivacyList(List.of(uuid)).get(0);
			expected.setAddress(makeUserLogin());
			expected.setCompany(makeUserLogin());
			expected.setCountry(Locale.getDefault().getISO3Country());
			expected.setLang(Locale.getDefault().getISO3Language());
			expected.setEmail(makeUserLogin());
			expected.setName(makeRandomThing());
			expected.setPhone(makeUserLogin());
			expected.setPostalcode(StringUtils.abbreviate(makeUserLogin(), 16));

			mvc.perform(put(baseMapping + "/" + "users/" + uuid + "/privacy")
			        .headers(baseHeaders)
			        .contentType(APPLICATION_JSON_UTF8)
			        .content(objectMapper.writeValueAsString(expected)))
			        .andExpect(statusOkUtf8Hateoas);

			final var afterUpdate = authenticationService.getUserPrivacyList(List.of(uuid)).get(0);
			assertEquals(expected, afterUpdate);
		}

	}

	// .andDo(MockMvcResultHandlers.print())
	/**
	 * See https://www.petrikainulainen.net/programming/spring-framework/integration-testing-of-spring-mvc-applications-write-clean-assertions-with-jsonpath/
	 * See https://docs.spring.io/spring-boot/docs/current/reference/html/boot-features-testing.html
	 */
	// .andExpect(MockMvcResultMatchers.jsonPath("$.employees").exists())
	// .andExpect(MockMvcResultMatchers.jsonPath("$.employees[*].employeeId").isNotEmpty());
	// .andExpect(content().string(containsString("")));
}
