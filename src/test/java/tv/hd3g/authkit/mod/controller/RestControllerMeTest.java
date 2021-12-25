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

import static java.time.Duration.ofDays;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static tv.hd3g.authkit.mod.service.TOTPServiceImpl.base32;
import static tv.hd3g.authkit.mod.service.TOTPServiceImpl.makeCodeAtTime;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomThing;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserLogin;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserPassword;
import static tv.hd3g.authkit.tool.DataGenerator.thirtyDays;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.web.bind.annotation.RequestMapping;

import com.fasterxml.jackson.databind.ObjectMapper;

import tv.hd3g.authkit.mod.dto.Password;
import tv.hd3g.authkit.mod.dto.ressource.UserPrivacyDto;
import tv.hd3g.authkit.mod.dto.validated.AddUserDto;
import tv.hd3g.authkit.mod.dto.validated.LoginFormDto;
import tv.hd3g.authkit.mod.repository.CredentialRepository;
import tv.hd3g.authkit.mod.service.AuthenticationService;
import tv.hd3g.authkit.mod.service.SecuredTokenService;
import tv.hd3g.authkit.mod.service.TOTPService;
import tv.hd3g.authkit.tool.ChangeMyPasswordTestDto;
import tv.hd3g.authkit.tool.DataGenerator;
import tv.hd3g.authkit.tool.ValidationSetupTOTPTestDto;
import tv.hd3g.authkit.tool.ValidationTOTPTestDto;

@SpringBootTest
@AutoConfigureMockMvc
class RestControllerMeTest {

	private static final String baseMapping = RestControllerMe.class.getAnnotation(RequestMapping.class).value()[0];

	private static final ResultMatcher statusOk = status().isOk();
	private static final ResultMatcher statusBadRequest = status().isBadRequest();
	private static final ResultMatcher contentTypeJsonUtf8 = content().contentType(APPLICATION_JSON_VALUE);
	private static final ResultMatcher[] statusOkUtf8 = new ResultMatcher[] { statusOk, contentTypeJsonUtf8 };

	@Autowired
	private MockMvc mvc;
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private AuthenticationService authenticationService;
	@Autowired
	private SecuredTokenService securedTokenService;
	@Autowired
	private CredentialRepository credentialRepository;
	@Autowired
	private TOTPService totpService;
	@Value("${authkit.totpTimeStepSeconds:30}")
	private int timeStepSeconds;

	private HttpHeaders baseHeaders;

	@Mock
	private HttpServletRequest request;

	private String userLogin;
	private String userUUID;
	private String userPassword;

	@BeforeEach
	private void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		DataGenerator.setupMock(request);

		final var addUser = new AddUserDto();
		userLogin = makeUserLogin();
		userPassword = makeUserPassword();
		addUser.setUserLogin(userLogin);
		addUser.setUserPassword(new Password(userPassword));
		userUUID = authenticationService.addUser(addUser);

		final var authToken = securedTokenService.loggedUserRightsGenerateToken(userUUID, ofDays(1), Set.of(), null);
		baseHeaders = new HttpHeaders();
		baseHeaders.set(AUTHORIZATION, "bearer " + authToken);
		baseHeaders.setAccept(Arrays.asList(APPLICATION_JSON));
	}

	@Test
	void changeMyPassword() throws Exception {
		final var chPasswordDto = new ChangeMyPasswordTestDto();
		chPasswordDto.setCurrentpassword(userPassword);
		final var newPassword = makeUserPassword();
		chPasswordDto.setNewpassword(newPassword);

		mvc.perform(post(baseMapping + "/" + "chpasswd")
		        .headers(baseHeaders)
		        .contentType(APPLICATION_JSON_VALUE)
		        .content(objectMapper.writeValueAsString(chPasswordDto)))
		        .andExpect(statusOk);

		final var loginForm = new LoginFormDto();
		loginForm.setUserlogin(userLogin);
		loginForm.setUserpassword(new Password(newPassword));

		final var sessionToken = authenticationService.userLoginRequest(request, loginForm);
		assertNotNull(sessionToken);
	}

	@Test
	void prepareTOTP() throws Exception {
		mvc.perform(get(baseMapping + "/" + "set2auth")
		        .headers(baseHeaders))
		        .andExpectAll(statusOkUtf8)
		        .andExpect(jsonPath("$.secret").isString())
		        .andExpect(jsonPath("$.totpURI").isString())
		        .andExpect(jsonPath("$.qrcode").isString())
		        .andExpect(jsonPath("$.backupCodes").isArray())
		        .andExpect(jsonPath("$.jwtControl").isString());
	}

	@Test
	void prepareTOTP_userAlreadyHaveTOTP() throws Exception {
		final var secret = totpService.makeSecret();
		final var backupCodes = totpService.makeBackupCodes();
		totpService.setupTOTP(secret, backupCodes, userUUID);

		mvc.perform(get(baseMapping + "/" + "set2auth")
		        .headers(baseHeaders))
		        .andExpect(statusBadRequest)
		        .andExpect(contentTypeJsonUtf8)
		        .andExpect(jsonPath("$.message").isString());
	}

	@Test
	void confirmTOTP() throws Exception {
		final var secret = totpService.makeSecret();
		final var backupCodes = totpService.makeBackupCodes();
		final var setupDto = new ValidationSetupTOTPTestDto();
		final var checkCode = makeCodeAtTime(base32.decode(secret), System.currentTimeMillis(), timeStepSeconds);
		setupDto.setTwoauthcode(checkCode);
		final var controlToken = securedTokenService.setupTOTPGenerateToken(userUUID, thirtyDays, secret, backupCodes);
		setupDto.setControlToken(controlToken);
		setupDto.setCurrentpassword(userPassword);

		mvc.perform(post(baseMapping + "/" + "set2auth")
		        .headers(baseHeaders)
		        .contentType(APPLICATION_JSON_VALUE)
		        .content(objectMapper.writeValueAsString(setupDto)))
		        .andExpect(statusOk);
	}

	@Test
	void confirmTOTP_userAlreadyHaveTOTP() throws Exception {
		final var secret = totpService.makeSecret();
		final var backupCodes = totpService.makeBackupCodes();
		totpService.setupTOTP(secret, backupCodes, userUUID);

		final var setupDtoSecond = new ValidationSetupTOTPTestDto();
		final var checkCodeSecond = makeCodeAtTime(base32.decode(secret), System.currentTimeMillis(), timeStepSeconds);
		setupDtoSecond.setTwoauthcode(checkCodeSecond);
		final var controlTokenSecond = securedTokenService.setupTOTPGenerateToken(userUUID, thirtyDays, secret,
		        backupCodes);
		setupDtoSecond.setControlToken(controlTokenSecond);
		setupDtoSecond.setCurrentpassword(userPassword);

		mvc.perform(post(baseMapping + "/" + "set2auth")
		        .headers(baseHeaders)
		        .contentType(APPLICATION_JSON_VALUE)
		        .content(objectMapper.writeValueAsString(setupDtoSecond)))
		        .andExpect(statusBadRequest);
	}

	@Test
	void hasATOTP_yes() throws Exception {
		final var secret = totpService.makeSecret();
		final var backupCodes = totpService.makeBackupCodes();
		totpService.setupTOTP(secret, backupCodes, userUUID);

		mvc.perform(get(baseMapping + "/" + "has2auth")
		        .headers(baseHeaders))
		        .andExpectAll(statusOkUtf8)
		        .andExpect(jsonPath("$.twoAuthEnabled").isBoolean())
		        .andExpect(jsonPath("$.twoAuthEnabled").value(true));
	}

	@Test
	void hasATOTP_no() throws Exception {
		mvc.perform(get(baseMapping + "/" + "has2auth")
		        .headers(baseHeaders))
		        .andExpectAll(statusOkUtf8)
		        .andExpect(jsonPath("$.twoAuthEnabled").isBoolean())
		        .andExpect(jsonPath("$.twoAuthEnabled").value(false));
	}

	@Test
	void removeTOTP() throws Exception {
		final var secret = totpService.makeSecret();
		final var backupCodes = totpService.makeBackupCodes();
		totpService.setupTOTP(secret, backupCodes, userUUID);

		final var checkCode = makeCodeAtTime(base32.decode(secret), System.currentTimeMillis(), timeStepSeconds);
		final var setupDto = new ValidationTOTPTestDto();
		setupDto.setCurrentpassword(userPassword);
		setupDto.setTwoauthcode(checkCode);

		mvc.perform(delete(baseMapping + "/" + "set2auth")
		        .headers(baseHeaders)
		        .contentType(APPLICATION_JSON_VALUE)
		        .content(objectMapper.writeValueAsString(setupDto)))
		        .andExpect(statusOk);
	}

	@Test
	void isExternalAuth_no() throws Exception {
		mvc.perform(get(baseMapping + "/" + "is-external-auth")
		        .headers(baseHeaders))
		        .andExpectAll(statusOkUtf8)
		        .andExpect(jsonPath("$.externalAuthEnabled").isBoolean())
		        .andExpect(jsonPath("$.externalAuthEnabled").value(false));
	}

	@Test
	void isExternalAuth_yes() throws Exception {
		final var c = credentialRepository.getByUserUUID(userUUID);
		final var domain = makeUserLogin();
		c.setLdapdomain(domain);
		credentialRepository.save(c);

		mvc.perform(get(baseMapping + "/" + "is-external-auth")
		        .headers(baseHeaders))
		        .andExpectAll(statusOkUtf8)
		        .andExpect(jsonPath("$.externalAuthEnabled").isBoolean())
		        .andExpect(jsonPath("$.externalAuthEnabled").value(true))
		        .andExpect(jsonPath("$.domain").isString())
		        .andExpect(jsonPath("$.domain").value(domain));
	}

	@Nested
	class Privacy {

		UserPrivacyDto userPrivacyDto;

		@BeforeEach
		void init() {
			userPrivacyDto = new UserPrivacyDto();
			userPrivacyDto.setAddress(makeUserLogin());
			userPrivacyDto.setCompany(makeUserLogin());
			userPrivacyDto.setCountry(Locale.getDefault().getISO3Country());
			userPrivacyDto.setLang(Locale.getDefault().getISO3Language());
			userPrivacyDto.setEmail(makeUserLogin());
			userPrivacyDto.setName(makeRandomThing());
			userPrivacyDto.setPhone(makeUserLogin());
			userPrivacyDto.setPostalcode(StringUtils.abbreviate(makeUserLogin(), 16));
			authenticationService.setUserPrivacy(userUUID, userPrivacyDto);
		}

		@Test
		void getPrivacy() throws Exception {
			final var expected = authenticationService.getUserPrivacyList(List.of(userUUID)).get(0);

			mvc.perform(get(baseMapping + "/" + "privacy")
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
			        .andExpectAll(statusOkUtf8);
		}

		@Test
		void setPrivacy() throws Exception {
			final var expected = authenticationService.getUserPrivacyList(List.of(userUUID)).get(0);
			expected.setAddress(makeUserLogin());
			expected.setCompany(makeUserLogin());
			expected.setCountry(Locale.getDefault().getISO3Country());
			expected.setLang(Locale.getDefault().getISO3Language());
			expected.setEmail(makeUserLogin());
			expected.setName(makeRandomThing());
			expected.setPhone(makeUserLogin());
			expected.setPostalcode(StringUtils.abbreviate(makeUserLogin(), 16));

			mvc.perform(put(baseMapping + "/" + "privacy")
			        .headers(baseHeaders)
			        .contentType(APPLICATION_JSON_VALUE)
			        .content(objectMapper.writeValueAsString(expected)))
			        .andExpect(statusOk);

			final var afterUpdate = authenticationService.getUserPrivacyList(List.of(userUUID)).get(0);
			assertEquals(expected, afterUpdate);
		}

	}

}
