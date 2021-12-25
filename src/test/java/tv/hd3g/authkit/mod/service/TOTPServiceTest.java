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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static tv.hd3g.authkit.mod.service.CookieService.AUTH_COOKIE_NAME;
import static tv.hd3g.authkit.mod.service.TOTPServiceImpl.base32;
import static tv.hd3g.authkit.mod.service.TOTPServiceImpl.makeCodeAtTime;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserLogin;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserPassword;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Random;

import javax.imageio.ImageIO;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;

import tv.hd3g.authkit.mod.dto.LoggedUserTagsTokenDto;
import tv.hd3g.authkit.mod.dto.LoginRequestContentDto;
import tv.hd3g.authkit.mod.dto.Password;
import tv.hd3g.authkit.mod.dto.validated.AddUserDto;
import tv.hd3g.authkit.mod.dto.validated.LoginFormDto;
import tv.hd3g.authkit.mod.entity.Credential;
import tv.hd3g.authkit.mod.entity.User;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.BadTOTPCodeCantLoginException;
import tv.hd3g.authkit.mod.repository.CredentialRepository;
import tv.hd3g.authkit.tool.DataGenerator;

@SpringBootTest
class TOTPServiceTest {

	@Autowired
	private TOTPService totpService;
	@Autowired
	private AuthenticationService authenticationService;
	@Autowired
	private SecuredTokenService securedTokenService;
	@Autowired
	private CredentialRepository credentialRepository;

	@Value("${authkit.backupCodeQuantity:6}")
	private int backupCodeQuantity;
	@Value("${authkit.totpTimeStepSeconds:30}")
	private int timeStepSeconds;
	@Value("${authkit.totpWindowMillis:5000}")
	private long windowMillis;

	@Test
	void makeSecret() {
		final var secret = totpService.makeSecret();
		assertNotNull(secret);
		final var base32 = new Base32(false);
		final var binSecret = base32.decode(secret);
		assertNotNull(binSecret);
		assertTrue(binSecret.length > 0);
	}

	@Test
	void makeURI() {
		final var secret = totpService.makeSecret();
		final var user = new User();
		final var login = makeUserLogin();
		user.setCredential(new Credential(user, login, null, null, false, false));
		final var domain = makeUserLogin();

		final var uri = totpService.makeURI(secret, user, domain);
		assertEquals("otpauth://totp/" + login + "@" + domain + "?secret=" + secret, uri.toString());
	}

	@Test
	void makeQRCode() throws NotFoundException, IOException, URISyntaxException {
		final var uri = new URI(
		        "otpauth://totp/" + makeUserLogin() + "@" + makeUserLogin() + "?secret=" + makeUserLogin());
		final var qr = totpService.makeQRCode(uri);
		final var source = new ByteArrayInputStream(Base64.getDecoder().decode(qr));
		final var binaryBitmap = new BinaryBitmap(new HybridBinarizer(
		        new BufferedImageLuminanceSource(ImageIO.read(source))));
		final var qrCodeResult = new MultiFormatReader().decode(binaryBitmap);
		final var decoded = qrCodeResult.getText();

		assertEquals(uri.toString(), decoded);
	}

	@Test
	void makeBackupCodes() {
		assertEquals(backupCodeQuantity, totpService.makeBackupCodes().size());
		assertTrue(totpService.makeBackupCodes().stream()
		        .allMatch(code -> code.length() == 6 && Integer.parseInt(code) >= 0));
	}

	@Test
	void checkCode() throws BadTOTPCodeCantLoginException, GeneralSecurityException {
		final var addUser = new AddUserDto();
		addUser.setUserLogin(makeUserLogin());
		final var userPassword = makeUserPassword();
		addUser.setUserPassword(new Password(userPassword));
		final var uuid = authenticationService.addUser(addUser);
		final var secret = totpService.makeSecret();
		final var backupCodes = totpService.makeBackupCodes();
		totpService.setupTOTP(secret, backupCodes, uuid);

		final var binSecret = base32.decode(secret);
		final var code = makeCodeAtTime(binSecret, System.currentTimeMillis(), timeStepSeconds);
		final var code2 = makeCodeAtTime(binSecret, System.currentTimeMillis(), timeStepSeconds);
		assertEquals(code, code2);

		totpService.checkCode(credentialRepository.getByUserUUID(uuid), code);
	}

	@Test
	void checkCode_withBackupCode() throws BadTOTPCodeCantLoginException, GeneralSecurityException {
		final var addUser = new AddUserDto();
		addUser.setUserLogin(makeUserLogin());
		final var userPassword = makeUserPassword();
		addUser.setUserPassword(new Password(userPassword));
		final var uuid = authenticationService.addUser(addUser);
		final var secret = totpService.makeSecret();
		final var backupCodes = totpService.makeBackupCodes();
		totpService.setupTOTP(secret, backupCodes, uuid);

		for (final String code : backupCodes) {
			totpService.checkCode(credentialRepository.getByUserUUID(uuid), code);
		}

		for (final String code : backupCodes) {
			Assertions.assertThrows(BadTOTPCodeCantLoginException.class, () -> {
				totpService.checkCode(credentialRepository.getByUserUUID(uuid), code);
			});
		}

	}

	@Test
	void checkCode_fail() {
		final var addUser = new AddUserDto();
		addUser.setUserLogin(makeUserLogin());
		final var userPassword = makeUserPassword();
		addUser.setUserPassword(new Password(userPassword));
		final var uuid = authenticationService.addUser(addUser);
		final var secret = totpService.makeSecret();
		final var backupCodes = totpService.makeBackupCodes();
		totpService.setupTOTP(secret, backupCodes, uuid);
		final var credential = credentialRepository.getByUserUUID(uuid);

		Assertions.assertThrows(BadTOTPCodeCantLoginException.class,
		        () -> totpService.checkCode(credential, "-1"));
	}

	@Test
	void makeCodeAtTime_overTime() throws GeneralSecurityException {
		final var secret = totpService.makeSecret();
		final var binSecret = base32.decode(secret);
		final var now = System.currentTimeMillis();
		final var code = makeCodeAtTime(binSecret, now, timeStepSeconds);
		final var code2 = makeCodeAtTime(binSecret, now + timeStepSeconds * 1000l * 2l, timeStepSeconds);
		final var code3 = makeCodeAtTime(binSecret, now - timeStepSeconds * 1000l * 2l, timeStepSeconds);
		assertNotEquals(code, code2);
		assertNotEquals(code, code3);
	}

	@Test
	void checkCode_underTime() throws GeneralSecurityException, BadTOTPCodeCantLoginException {
		final var addUser = new AddUserDto();
		addUser.setUserLogin(makeUserLogin());
		final var userPassword = makeUserPassword();
		addUser.setUserPassword(new Password(userPassword));
		final var uuid = authenticationService.addUser(addUser);
		final var secret = totpService.makeSecret();
		final var backupCodes = totpService.makeBackupCodes();
		totpService.setupTOTP(secret, backupCodes, uuid);
		final var credential = credentialRepository.getByUserUUID(uuid);

		final var binSecret = base32.decode(secret);
		final var now = System.currentTimeMillis();
		final var code1 = makeCodeAtTime(binSecret, now + windowMillis / 2, timeStepSeconds);
		totpService.checkCode(credential, code1);

		final var code2 = makeCodeAtTime(binSecret, now - windowMillis / 2, timeStepSeconds);
		totpService.checkCode(credential, code2);
	}

	@Test
	void checkCode_bruteForce() throws GeneralSecurityException {
		final var addUser = new AddUserDto();
		addUser.setUserLogin(makeUserLogin());
		final var userPassword = makeUserPassword();
		addUser.setUserPassword(new Password(userPassword));
		final var uuid = authenticationService.addUser(addUser);
		final var secret = totpService.makeSecret();
		final var backupCodes = totpService.makeBackupCodes();
		totpService.setupTOTP(secret, backupCodes, uuid);
		final var credential = credentialRepository.getByUserUUID(uuid);

		final var r = new Random();
		final var someRandoms = r.ints(500, 0, 1_000_000).mapToObj(i -> i).collect(toUnmodifiableList());
		for (final int code : someRandoms) {
			Assertions.assertThrows(BadTOTPCodeCantLoginException.class,
			        () -> totpService.checkCode(credential, String.valueOf(code)));
		}
	}

	@Test
	void removeTOTP() throws UserCantLoginException {
		final var addUser = new AddUserDto();
		addUser.setUserLogin(makeUserLogin());
		final var userPassword = makeUserPassword();
		addUser.setUserPassword(new Password(userPassword));
		final var uuid = authenticationService.addUser(addUser);
		final var secret = totpService.makeSecret();
		final var backupCodes = totpService.makeBackupCodes();
		totpService.setupTOTP(secret, backupCodes, uuid);
		final var credential = credentialRepository.getByUserUUID(uuid);
		totpService.removeTOTP(credential);

		final var loginForm = new LoginFormDto();
		loginForm.setUserlogin(addUser.getUserLogin());
		loginForm.setUserpassword(new Password(userPassword));
		final var request = mock(HttpServletRequest.class);
		DataGenerator.setupMock(request);

		checkLoginRequestContent(authenticationService.userLoginRequest(request, loginForm), uuid);
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

}
