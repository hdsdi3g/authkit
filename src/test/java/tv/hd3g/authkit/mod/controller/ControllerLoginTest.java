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

import static io.jsonwebtoken.SignatureAlgorithm.HS512;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.Duration.ZERO;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static tv.hd3g.authkit.mod.controller.ControllerLogin.TOKEN_FORMNAME_ENTER_TOTP;
import static tv.hd3g.authkit.mod.controller.ControllerLogin.TOKEN_FORMNAME_LOGIN;
import static tv.hd3g.authkit.mod.controller.ControllerLogin.TOKEN_FORMNAME_RESET_PSD;
import static tv.hd3g.authkit.mod.controller.ControllerLogin.TOKEN_REDIRECT_RESET_PSD;
import static tv.hd3g.authkit.mod.service.SecuredTokenServiceImpl.TOKEN_AUDIENCE;
import static tv.hd3g.authkit.mod.service.SecuredTokenServiceImpl.TOKEN_ISSUER_FORM;
import static tv.hd3g.authkit.mod.service.SecuredTokenServiceImpl.TOKEN_TYPE;
import static tv.hd3g.authkit.mod.service.TOTPServiceImpl.base32;
import static tv.hd3g.authkit.mod.service.TOTPServiceImpl.makeCodeAtTime;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomBytes;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserLogin;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserPassword;
import static tv.hd3g.authkit.tool.DataGenerator.thirtyDays;

import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.web.util.UriUtils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import tv.hd3g.authkit.mod.dto.Password;
import tv.hd3g.authkit.mod.dto.validated.AddUserDto;
import tv.hd3g.authkit.mod.dto.validated.LoginFormDto;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.BadPasswordUserCantLoginException;
import tv.hd3g.authkit.mod.service.AuthenticationService;
import tv.hd3g.authkit.mod.service.SecuredTokenService;
import tv.hd3g.authkit.mod.service.TOTPService;
import tv.hd3g.authkit.tool.AddUserTestDto;
import tv.hd3g.authkit.tool.DataGenerator;

@SpringBootTest
@AutoConfigureMockMvc
public class ControllerLoginTest {

	private static final MediaType TEXT_HTML_UTF8 = new MediaType("text", "html", UTF_8);

	private final ResultMatcher statusOk = status().isOk();
	private final ResultMatcher statusBadRequest = status().isBadRequest();
	private final ResultMatcher statusUnauthorized = status().isUnauthorized();
	private final ResultMatcher loginView = view().name("login");
	private final ResultMatcher contentTypeHtmlUtf8 = content().contentType(TEXT_HTML_UTF8);
	private final ResultMatcher modelHasNoErrors = model().hasNoErrors();
	private final ResultMatcher modelHasErrors = model().hasErrors();
	private final ResultMatcher modelHasFormtokenAttr = model().attributeExists("formtoken");
	private final ResultMatcher modelHasSessionAttr = model().attributeExists("jwtsession");
	private final ResultMatcher modelHasNoSessionAttr = model().attributeDoesNotExist("jwtsession");
	private final ResultMatcher modelHasErrorAttr = model().attributeExists("error");
	private final ResultMatcher modelHasActionDoneAttr = model().attributeExists("actionDone");

	@Autowired
	private MockMvc mvc;

	@Autowired
	private SecuredTokenService tokenService;
	@Autowired
	private AuthenticationService authenticationService;
	@Autowired
	private TOTPService totpService;
	@Value("${authkit.maxLogonTrial:10}")
	private short maxLogonTrial;
	@Value("${authkit.totpTimeStepSeconds:30}")
	private int timeStepSeconds;

	@Test
	public void login() throws Exception {
		mvc.perform(get("/login")
		        .accept(TEXT_HTML))
		        .andExpect(statusOk)
		        .andExpect(loginView)
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasNoErrors)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasFormtokenAttr);
	}

	@Test
	public void doLogin_NothingSend() throws Exception {
		mvc.perform(post("/login")
		        .accept(TEXT_HTML))
		        .andExpect(statusBadRequest)
		        .andExpect(loginView)
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasErrors)
		        .andExpect(modelHasErrorAttr)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasFormtokenAttr);
	}

	@Test
	public void doLogin_InvalidUserPassword() throws Exception {
		final var validToken = tokenService.simpleFormGenerateToken(TOKEN_FORMNAME_LOGIN, thirtyDays);
		mvc.perform(post("/login").contentType(APPLICATION_FORM_URLENCODED)
		        .content(createUserBadPassword(validToken).makeForm())
		        .accept(TEXT_HTML))
		        .andExpect(statusUnauthorized)
		        .andExpect(loginView)
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasNoErrors)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasErrorAttr);
	}

	@Test
	public void doLogin_BlockedUser() throws Exception {
		final var validToken = tokenService.simpleFormGenerateToken(TOKEN_FORMNAME_LOGIN, thirtyDays);

		final var addUser = new AddUserTestDto();
		final var uuid = authenticationService.addUser(addUser.makeClassicDto());
		final var userBadPasswordForm = new FormHandler(addUser.getUserLogin(), makeUserPassword(),
		        validToken, uuid);
		final var userValidPasswordForm = new FormHandler(addUser.getUserLogin(), addUser.getUserPassword(),
		        validToken, uuid);

		for (int pos = 0; pos < maxLogonTrial; pos++) {
			mvc.perform(post("/login").contentType(APPLICATION_FORM_URLENCODED)
			        .content(userBadPasswordForm.makeForm())
			        .accept(TEXT_HTML)).andExpect(statusUnauthorized);
		}

		mvc.perform(post("/login").contentType(APPLICATION_FORM_URLENCODED)
		        .content(userValidPasswordForm.makeForm())
		        .accept(TEXT_HTML))
		        .andExpect(statusUnauthorized)
		        .andExpect(loginView)
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasNoErrors)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasErrorAttr);
	}

	@Test
	public void doLogin_EmptyForm() throws Exception {
		mvc.perform(post("/login").contentType(APPLICATION_FORM_URLENCODED)
		        .content(createFormLoginContent("", "", ""))
		        .accept(TEXT_HTML))
		        .andExpect(statusBadRequest)
		        .andExpect(loginView)
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasErrors)
		        .andExpect(modelHasErrorAttr)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasFormtokenAttr);
	}

	@Test
	public void doLogin_EmptyFormLogin() throws Exception {
		final var validToken = tokenService.simpleFormGenerateToken(TOKEN_FORMNAME_LOGIN, thirtyDays);

		mvc.perform(post("/login").contentType(APPLICATION_FORM_URLENCODED)
		        .content(createFormLoginContent("", "", validToken))
		        .accept(TEXT_HTML))
		        .andExpect(statusBadRequest)
		        .andExpect(loginView)
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasErrors)
		        .andExpect(modelHasErrorAttr)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasFormtokenAttr);
	}

	@Test
	public void doLogin_EmptyToken() throws Exception {
		mvc.perform(post("/login").contentType(APPLICATION_FORM_URLENCODED)
		        .content(createUser("").makeForm())
		        .accept(TEXT_HTML))
		        .andExpect(statusBadRequest)
		        .andExpect(loginView)
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasErrors)
		        .andExpect(modelHasErrorAttr)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasFormtokenAttr);
	}

	@Test
	public void doLogin_InvalidToken() throws Exception {
		final long now = System.currentTimeMillis();
		final byte[] secret = makeRandomBytes(128);

		final var invalidToken = Jwts.builder()
		        .signWith(Keys.hmacShaKeyFor(secret), HS512)
		        .setHeaderParam("typ", TOKEN_TYPE)
		        .setIssuer(TOKEN_ISSUER_FORM)
		        .setAudience(TOKEN_AUDIENCE)
		        // .setSubject("(none)")
		        .setExpiration(new Date(now + thirtyDays.toMillis()))
		        .claim("formname", TOKEN_FORMNAME_LOGIN)
		        .compact();

		mvc.perform(post("/login").contentType(APPLICATION_FORM_URLENCODED)
		        .content(createUser(invalidToken).makeForm())
		        .accept(TEXT_HTML))
		        .andExpect(statusBadRequest)
		        .andExpect(loginView)
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasNoErrors)
		        .andExpect(modelHasErrorAttr)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasFormtokenAttr);
	}

	@Test
	public void doLogin_OldToken() throws Exception {
		final var oldToken = tokenService.simpleFormGenerateToken(TOKEN_FORMNAME_LOGIN, ZERO);

		mvc.perform(post("/login").contentType(APPLICATION_FORM_URLENCODED)
		        .content(createUser(oldToken).makeForm())
		        .accept(TEXT_HTML))
		        .andExpect(statusBadRequest)
		        .andExpect(loginView)
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasNoErrors)
		        .andExpect(modelHasErrorAttr)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasFormtokenAttr);
	}

	@Test
	public void doLogin_Ok() throws Exception {
		final var validToken = tokenService.simpleFormGenerateToken(TOKEN_FORMNAME_LOGIN, thirtyDays);
		mvc.perform(post("/login").contentType(APPLICATION_FORM_URLENCODED)
		        .content(createUser(validToken).makeForm())
		        .accept(TEXT_HTML))
		        .andExpect(statusOk)
		        .andExpect(view().name("bounce-session"))
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasSessionAttr)
		        .andExpect(modelHasNoErrors);
	}

	@Test
	public void doLogin_Disabled() throws Exception {
		final var validToken = tokenService.simpleFormGenerateToken(TOKEN_FORMNAME_LOGIN, thirtyDays);
		mvc.perform(post("/login").contentType(APPLICATION_FORM_URLENCODED)
		        .content(createDisabledUser(validToken).makeForm())
		        .accept(TEXT_HTML))
		        .andExpect(statusUnauthorized)
		        .andExpect(loginView)
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasNoErrors)
		        .andExpect(modelHasErrorAttr)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasFormtokenAttr);
	}

	@Test
	public void doLogin_MustChangePassword() throws Exception {
		final var validToken = tokenService.simpleFormGenerateToken(TOKEN_FORMNAME_LOGIN, thirtyDays);
		final var form = createUserMustChangePassword(validToken);
		final var resultActions = mvc.perform(post("/login").contentType(APPLICATION_FORM_URLENCODED)
		        .content(form.makeForm())
		        .accept(TEXT_HTML))
		        .andExpect(statusOk)
		        .andExpect(view().name("reset-password"))
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasNoErrors).andReturn();

		final var resetPasswordToken = (String) resultActions.getModelAndView().getModel().get("formtoken");
		final var uuid = tokenService.userFormExtractTokenUUID(TOKEN_FORMNAME_RESET_PSD, resetPasswordToken);
		assertEquals(form.uuid, uuid);
	}

	@Test
	public void logout() throws Exception {
		mvc.perform(get("/logout")
		        .accept(TEXT_HTML))
		        .andExpect(statusOk)
		        .andExpect(view().name("bounce-logout"))
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasNoErrors);
	}

	@Test
	public void doResetPassword() throws Exception {
		final var userPassword = makeUserPassword();
		final var addUser = new AddUserDto();
		addUser.setUserLogin(makeUserLogin());
		addUser.setUserPassword(new Password(userPassword));
		final var userUUID = authenticationService.addUser(addUser);
		authenticationService.setUserMustChangePassword(userUUID);

		final var resetPasswordToken = tokenService.userFormGenerateToken(
		        TOKEN_FORMNAME_RESET_PSD, userUUID, thirtyDays);
		final var newUserPassword = makeUserPassword();

		final var resultActions = mvc.perform(post("/reset-password").contentType(APPLICATION_FORM_URLENCODED)
		        .content(createResetPasswordFormContent(newUserPassword, resetPasswordToken))
		        .accept(TEXT_HTML))
		        .andExpect(statusOk)
		        .andExpect(view().name("login"))
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasActionDoneAttr)
		        .andExpect(modelHasFormtokenAttr)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasNoErrors).andReturn();

		/**
		 * Test login with the new password
		 */
		final var validToken = (String) resultActions.getModelAndView().getModel().get("formtoken");
		mvc.perform(post("/login").contentType(APPLICATION_FORM_URLENCODED)
		        .content(createFormLoginContent(addUser.getUserLogin(), newUserPassword, validToken))
		        .accept(TEXT_HTML))
		        .andExpect(statusOk)
		        .andExpect(view().name("bounce-session"))
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasSessionAttr)
		        .andExpect(modelHasNoErrors);
	}

	@Test
	public void doResetPassword_NotSameInputPassword() throws Exception {
		final var userPassword = makeUserPassword();
		final var addUser = new AddUserDto();
		addUser.setUserLogin(makeUserLogin());
		addUser.setUserPassword(new Password(userPassword));
		final var userUUID = authenticationService.addUser(addUser);
		authenticationService.setUserMustChangePassword(userUUID);

		final var resetPasswordToken = tokenService.userFormGenerateToken(
		        TOKEN_FORMNAME_RESET_PSD, userUUID, thirtyDays);
		mvc.perform(post("/reset-password").contentType(APPLICATION_FORM_URLENCODED)
		        .content(createFormContent(Map.of(
		                "newuserpassword", userPassword,
		                "newuserpassword2", makeUserPassword(),
		                "securetoken", resetPasswordToken)))
		        .accept(TEXT_HTML))
		        .andExpect(statusBadRequest)
		        .andExpect(view().name("reset-password"))
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasErrorAttr)
		        .andExpect(modelHasFormtokenAttr)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasNoErrors).andReturn();

		/**
		 * Test login with the same password, but without reset it before.
		 */
		final var validToken = tokenService.simpleFormGenerateToken(TOKEN_FORMNAME_LOGIN, thirtyDays);
		mvc.perform(post("/login").contentType(APPLICATION_FORM_URLENCODED)
		        .content(createFormLoginContent(addUser.getUserLogin(), userPassword, validToken))
		        .accept(TEXT_HTML))
		        .andExpect(statusOk)
		        .andExpect(view().name("reset-password"))
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasNoErrors);
	}

	@Test
	public void doResetPassword_SamePassword() throws Exception {
		final var userPassword = makeUserPassword();
		final var addUser = new AddUserDto();
		addUser.setUserLogin(makeUserLogin());
		addUser.setUserPassword(new Password(userPassword));
		final var userUUID = authenticationService.addUser(addUser);
		authenticationService.setUserMustChangePassword(userUUID);

		final var resetPasswordToken = tokenService.userFormGenerateToken(
		        TOKEN_FORMNAME_RESET_PSD, userUUID, thirtyDays);
		mvc.perform(post("/reset-password").contentType(APPLICATION_FORM_URLENCODED)
		        .content(createResetPasswordFormContent(userPassword, resetPasswordToken))
		        .accept(TEXT_HTML))
		        .andExpect(statusBadRequest)
		        .andExpect(view().name("reset-password"))
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasErrorAttr)
		        .andExpect(modelHasFormtokenAttr)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasNoErrors).andReturn();

		/**
		 * Test login with the same password, but without reset it before.
		 */
		final var validToken = tokenService.simpleFormGenerateToken(TOKEN_FORMNAME_LOGIN, thirtyDays);
		mvc.perform(post("/login").contentType(APPLICATION_FORM_URLENCODED)
		        .content(createFormLoginContent(addUser.getUserLogin(), userPassword, validToken))
		        .accept(TEXT_HTML))
		        .andExpect(statusOk)
		        .andExpect(view().name("reset-password"))
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasNoErrors);
	}

	@Test
	public void doResetPassword_BlockedUser() throws Exception {
		final var userPassword = makeUserPassword();
		final var addUser = new AddUserDto();
		addUser.setUserLogin(makeUserLogin());
		addUser.setUserPassword(new Password(userPassword));
		final var userUUID = authenticationService.addUser(addUser);
		final var loginFormFail = new LoginFormDto();
		loginFormFail.setUserlogin(addUser.getUserLogin());

		for (int pos = 0; pos < maxLogonTrial; pos++) {
			loginFormFail.setUserpassword(new Password(makeUserPassword()));
			final var request = Mockito.mock(HttpServletRequest.class);
			DataGenerator.setupMock(request);
			assertThrows(BadPasswordUserCantLoginException.class, () -> {
				authenticationService.userLoginRequest(request, loginFormFail);
			});
		}

		final var resetPasswordToken = tokenService.userFormGenerateToken(
		        TOKEN_FORMNAME_RESET_PSD, userUUID, thirtyDays);
		mvc.perform(post("/reset-password").contentType(APPLICATION_FORM_URLENCODED)
		        .content(createResetPasswordFormContent(userPassword, resetPasswordToken))
		        .accept(TEXT_HTML))
		        .andExpect(statusUnauthorized)
		        .andExpect(loginView)
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasNoErrors)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasErrorAttr);
	}

	@Test
	public void resetPassword_GetForm() throws Exception {
		final var addUser = new AddUserTestDto();
		final var uuid = authenticationService.addUser(addUser.makeClassicDto());
		final var token = tokenService.securedRedirectRequestGenerateToken(uuid, thirtyDays, TOKEN_REDIRECT_RESET_PSD);
		final var resultActions = mvc.perform(get("/reset-password/" + token)
		        .accept(TEXT_HTML))
		        .andExpect(statusOk)
		        .andExpect(view().name("reset-password"))
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasNoErrors)
		        .andExpect(modelHasFormtokenAttr).andReturn();
		final var userFormToken = (String) resultActions.getModelAndView().getModel().get("formtoken");
		assertEquals(uuid, tokenService.userFormExtractTokenUUID(TOKEN_FORMNAME_RESET_PSD, userFormToken));
	}

	@Test
	public void doTOTPLogin() throws Exception {
		final var addUser = new AddUserTestDto();
		final var uuid = authenticationService.addUser(addUser.makeClassicDto());
		final var secret = totpService.makeSecret();
		final var backupCodes = totpService.makeBackupCodes();
		final var checkCode = makeCodeAtTime(base32.decode(secret), System.currentTimeMillis(), timeStepSeconds);
		totpService.setupTOTP(secret, backupCodes, uuid);

		final var tokenAuth = tokenService.userFormGenerateToken(TOKEN_FORMNAME_ENTER_TOTP, uuid, thirtyDays);
		final var form2auth = createFormContent(Map.of(
		        "code", checkCode,
		        "securetoken", tokenAuth,
		        "shorttime", "false"));

		mvc.perform(post("/login-2auth").contentType(APPLICATION_FORM_URLENCODED)
		        .content(form2auth)
		        .accept(TEXT_HTML))
		        .andExpect(statusOk)
		        .andExpect(view().name("bounce-session"))
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasSessionAttr)
		        .andExpect(modelHasNoErrors);
	}

	@Test
	public void doLogin_TOTPAccount() throws Exception {
		final var validToken = tokenService.simpleFormGenerateToken(TOKEN_FORMNAME_LOGIN, thirtyDays);
		final var createUser = createUser(validToken);
		final var uuid = createUser.uuid;
		final var secret = totpService.makeSecret();
		final var backupCodes = totpService.makeBackupCodes();
		totpService.setupTOTP(secret, backupCodes, uuid);

		mvc.perform(post("/login").contentType(APPLICATION_FORM_URLENCODED)
		        .content(createUser.makeForm())
		        .accept(TEXT_HTML))
		        .andExpect(statusOk)
		        .andExpect(view().name("totp-challenge"))
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasNoErrors)
		        .andExpect(modelHasFormtokenAttr);
	}

	@Test
	public void doTOTPLogin_badCode() throws Exception {
		final var addUser = new AddUserTestDto();
		final var uuid = authenticationService.addUser(addUser.makeClassicDto());
		final var secret = totpService.makeSecret();
		final var backupCodes = totpService.makeBackupCodes();
		totpService.setupTOTP(secret, backupCodes, uuid);

		final var tokenAuth = tokenService.userFormGenerateToken(TOKEN_FORMNAME_ENTER_TOTP, uuid, thirtyDays);
		final var form2auth = createFormContent(Map.of(
		        "code", StringUtils.rightPad(String.valueOf(DataGenerator.random.nextInt(0, 1_000_000)), 6, "0"),
		        "securetoken", tokenAuth,
		        "shorttime", "false"));

		mvc.perform(post("/login-2auth").contentType(APPLICATION_FORM_URLENCODED)
		        .content(form2auth)
		        .accept(TEXT_HTML))
		        .andExpect(statusUnauthorized)
		        .andExpect(loginView)
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasNoErrors)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(modelHasErrorAttr);
	}

	private String createFormContent(final Map<String, String> content) throws Exception {
		final var inputList = content.entrySet().stream().map(formInput -> new BasicNameValuePair(formInput.getKey(),
		        UriUtils.encode(formInput.getValue(), UTF_8))).collect(Collectors.toUnmodifiableList());
		return EntityUtils.toString(new UrlEncodedFormEntity(inputList), UTF_8);
	}

	private String createResetPasswordFormContent(final String newUserPassword,
	                                              final String resetPasswordToken) throws Exception {
		return createFormContent(Map.of(
		        "newuserpassword", newUserPassword,
		        "newuserpassword2", newUserPassword,
		        "securetoken", resetPasswordToken));
	}

	private String createFormLoginContent(final String userlogin,
	                                      final String userpassword,
	                                      final String securetoken) throws Exception {
		return createFormContent(
		        Map.of("userlogin", userlogin, "userpassword", userpassword, "securetoken", securetoken));
	}

	private class FormHandler {
		private final String userlogin;
		private final String password;
		private final String securetoken;
		private final String uuid;

		FormHandler(final String userlogin, final String password, final String securetoken, final String uuid) {
			this.userlogin = userlogin;
			this.password = password;
			this.securetoken = securetoken;
			this.uuid = uuid;
		}

		String makeForm() throws Exception {
			return createFormLoginContent(userlogin, password, securetoken);
		}
	}

	private FormHandler createUser(final String securetoken) {
		final var addUser = new AddUserTestDto();
		final var uuid = authenticationService.addUser(addUser.makeClassicDto());
		return new FormHandler(addUser.getUserLogin(), addUser.getUserPassword(), securetoken, uuid);
	}

	private FormHandler createUserBadPassword(final String securetoken) {
		final var addUser = new AddUserTestDto();
		final var uuid = authenticationService.addUser(addUser.makeClassicDto());
		return new FormHandler(addUser.getUserLogin(), makeUserPassword(), securetoken, uuid);
	}

	private FormHandler createDisabledUser(final String securetoken) {
		final var addUser = new AddUserTestDto();
		final var userUUID = authenticationService.addUser(addUser.makeClassicDto());
		authenticationService.disableUser(userUUID);
		return new FormHandler(addUser.getUserLogin(), makeUserPassword(), securetoken, userUUID);
	}

	private FormHandler createUserMustChangePassword(final String securetoken) {
		final var addUser = new AddUserTestDto();
		final var userUUID = authenticationService.addUser(addUser.makeClassicDto());
		authenticationService.setUserMustChangePassword(userUUID);
		return new FormHandler(addUser.getUserLogin(), addUser.getUserPassword(), securetoken, userUUID);
	}

	// .andDo(MockMvcResultHandlers.print())
}
