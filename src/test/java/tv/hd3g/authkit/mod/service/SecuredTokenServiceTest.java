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

import static io.jsonwebtoken.SignatureAlgorithm.HS512;
import static java.time.Duration.ZERO;
import static java.util.stream.Collectors.toUnmodifiableList;
import static java.util.stream.Collectors.toUnmodifiableSet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static tv.hd3g.authkit.mod.service.SecuredTokenServiceImpl.TOKEN_AUDIENCE;
import static tv.hd3g.authkit.mod.service.SecuredTokenServiceImpl.TOKEN_ISSUER_FORM;
import static tv.hd3g.authkit.mod.service.SecuredTokenServiceImpl.TOKEN_ISSUER_LOGIN;
import static tv.hd3g.authkit.mod.service.SecuredTokenServiceImpl.TOKEN_ISSUER_SECUREDREQUEST;
import static tv.hd3g.authkit.mod.service.SecuredTokenServiceImpl.TOKEN_ISSUER_SETUPTOTP;
import static tv.hd3g.authkit.mod.service.SecuredTokenServiceImpl.TOKEN_TYPE;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomBytes;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomIPv4;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomString;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomThing;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomThings;
import static tv.hd3g.authkit.tool.DataGenerator.makeUUID;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserLogin;
import static tv.hd3g.authkit.tool.DataGenerator.thirtyDays;

import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.RequiredTypeException;
import io.jsonwebtoken.security.Keys;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException.BadUseSecuredTokenInvalidAudience;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException.BadUseSecuredTokenInvalidForm;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException.BadUseSecuredTokenInvalidIssuer;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException.BadUseSecuredTokenInvalidType;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException.BrokenSecuredToken;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException.ExpiredSecuredToken;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException.InvalidFormatSecuredToken;

@SpringBootTest
public class SecuredTokenServiceTest {

	@Autowired
	private SecuredTokenService securedTokenService;
	@Value("${authkit.jwt_secret}")
	private String base64secret;
	private byte[] secret;

	private final static Date inThirtyDays = new Date(System.currentTimeMillis() + thirtyDays.toMillis());

	private String formName;

	@BeforeEach
	public void init() {
		formName = makeRandomThing();
		secret = Base64.getDecoder().decode(base64secret.getBytes());
	}

	@Test
	public void simpleFormGenerateToken() {
		final String token = securedTokenService.simpleFormGenerateToken(formName, thirtyDays);
		assertNotNull(token);
	}

	@Nested
	class SimpleForm {

		@Test
		public void ok() throws NotAcceptableSecuredTokenException {
			final String token = securedTokenService.simpleFormGenerateToken(formName, thirtyDays);
			securedTokenService.simpleFormCheckToken(formName, token);
			Assertions.assertNotNull(token);
		}

		@Test
		public void invalidEmpty() {
			final String token = "";
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.simpleFormCheckToken(formName, token);
			});
		}

		@Test
		public void invalidNull() {
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.simpleFormCheckToken(formName, null);
			});
		}

		@Test
		public void invalidNotAJwt() {
			final var text = makeUserLogin();
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.simpleFormCheckToken(formName, text + "," + "text" + "," + text);
			});
		}

		@Test
		public void expired() {
			final String token = securedTokenService.simpleFormGenerateToken(formName, ZERO);
			assertThrows(ExpiredSecuredToken.class, () -> {
				securedTokenService.simpleFormCheckToken(formName, token);
			});
		}

		private String generateJwts(final Consumer<JwtBuilder> builder) {
			final var token = generateJwtsWithoutSign().signWith(Keys.hmacShaKeyFor(secret), HS512);
			builder.accept(token);
			return token.compact();
		}

		private JwtBuilder generateJwtsWithoutSign() {
			return Jwts.builder()
			        .setHeaderParam("typ", TOKEN_TYPE)
			        .setIssuer(TOKEN_ISSUER_FORM)
			        .setAudience(TOKEN_AUDIENCE)
			        .setExpiration(inThirtyDays)
			        .claim("formname", formName);
		}

		@Test
		public void invalidUnsupported() {
			final String token = generateJwtsWithoutSign().compact();
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.simpleFormCheckToken(formName, token);
			});
		}

		@Test
		public void broken() {
			final byte[] secret = makeRandomBytes(256);
			final String token = generateJwtsWithoutSign().signWith(Keys.hmacShaKeyFor(secret), HS512).compact();
			assertThrows(BrokenSecuredToken.class, () -> {
				securedTokenService.simpleFormCheckToken(formName, token);
			});
		}

		@Test
		public void badUse_issuer() {
			final String token = generateJwts(jwt -> {
				jwt.setIssuer(makeRandomThing());
			});
			assertThrows(BadUseSecuredTokenInvalidIssuer.class, () -> {
				securedTokenService.simpleFormCheckToken(formName, token);
			});
		}

		@Test
		public void badUse_audience() {
			final String token = generateJwts(jwt -> {
				jwt.setAudience(makeRandomThing());
			});
			assertThrows(BadUseSecuredTokenInvalidAudience.class, () -> {
				securedTokenService.simpleFormCheckToken(formName, token);
			});
		}

		@Test
		public void badUse_tokentype() {
			final String token = generateJwts(jwt -> {
				jwt.setHeaderParam("typ", makeRandomThing());
			});
			assertThrows(BadUseSecuredTokenInvalidType.class, () -> {
				securedTokenService.simpleFormCheckToken(formName, token);
			});
		}

		@Test
		public void badUse_tokenformName() {
			final String token = generateJwts(jwt -> {
				jwt.claim("formname", makeRandomThing());
			});
			assertThrows(BadUseSecuredTokenInvalidForm.class, () -> {
				securedTokenService.simpleFormCheckToken(formName, token);
			});
		}
	}

	@Test
	public void loggedUserRightsGenerateToken() {
		final String token = securedTokenService.loggedUserRightsGenerateToken(makeUUID(), thirtyDays, Set.of(), null);
		assertNotNull(token);
	}

	@Nested
	class LoggedUserRights {

		private String userUUID;
		private Set<String> tags;

		@BeforeEach
		public void init() {
			userUUID = makeUUID();
			tags = makeRandomThings().collect(toUnmodifiableSet());
		}

		@Test
		public void ok() throws NotAcceptableSecuredTokenException {
			final String token = securedTokenService.loggedUserRightsGenerateToken(userUUID, thirtyDays, tags, null);
			final var result = securedTokenService.loggedUserRightsExtractToken(token);
			assertEquals(userUUID, result.getUserUUID());
			assertEquals(tags, result.getTags());
			assertNull(result.getOnlyForHost());
		}

		@Test
		public void checkHost() throws NotAcceptableSecuredTokenException {
			final var host = makeRandomIPv4().getHostAddress();
			final String token = securedTokenService.loggedUserRightsGenerateToken(userUUID, thirtyDays, tags, host);
			final var result = securedTokenService.loggedUserRightsExtractToken(token);
			assertEquals(userUUID, result.getUserUUID());
			assertEquals(tags, result.getTags());
			assertEquals(host, result.getOnlyForHost());
		}

		@Test
		public void invalidEmpty() {
			final String token = "";
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.loggedUserRightsExtractToken(token);
			});
		}

		@Test
		public void invalidNull() {
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.loggedUserRightsExtractToken(null);
			});
		}

		@Test
		public void invalidNotAJwt() {
			final var text = makeUserLogin();
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.loggedUserRightsExtractToken(text + "," + "text" + "," + text);
			});
		}

		@Test
		public void expired() {
			final String token = securedTokenService.loggedUserRightsGenerateToken(userUUID, ZERO, tags, null);
			assertThrows(ExpiredSecuredToken.class, () -> {
				securedTokenService.loggedUserRightsExtractToken(token);
			});
		}

		private String generateJwts(final Consumer<JwtBuilder> builder) {
			final var token = generateJwtsWithoutSign().signWith(Keys.hmacShaKeyFor(secret), HS512);
			builder.accept(token);
			return token.compact();
		}

		private JwtBuilder generateJwtsWithoutSign() {
			return Jwts.builder()
			        .setHeaderParam("typ", TOKEN_TYPE)
			        .setIssuer(TOKEN_ISSUER_LOGIN)
			        .setAudience(TOKEN_AUDIENCE)
			        .setSubject(userUUID)
			        .setExpiration(inThirtyDays)
			        .claim("tags", tags);
		}

		@Test
		public void invalidUnsupported() {
			final String token = generateJwtsWithoutSign().compact();
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.loggedUserRightsExtractToken(token);
			});
		}

		@Test
		public void broken() {
			final byte[] secret = makeRandomBytes(256);
			final String token = generateJwtsWithoutSign().signWith(Keys.hmacShaKeyFor(secret), HS512).compact();
			assertThrows(BrokenSecuredToken.class, () -> {
				securedTokenService.loggedUserRightsExtractToken(token);
			});
		}

		@Test
		public void badUse_issuer() {
			final String token = generateJwts(jwt -> {
				jwt.setIssuer(makeRandomThing());
			});
			assertThrows(BadUseSecuredTokenInvalidIssuer.class, () -> {
				securedTokenService.loggedUserRightsExtractToken(token);
			});
		}

		@Test
		public void badUse_audience() {
			final String token = generateJwts(jwt -> {
				jwt.setAudience(makeRandomThing());
			});
			assertThrows(BadUseSecuredTokenInvalidAudience.class, () -> {
				securedTokenService.loggedUserRightsExtractToken(token);
			});
		}

		@Test
		public void badUse_tokentype() {
			final String token = generateJwts(jwt -> {
				jwt.setHeaderParam("typ", makeRandomThing());
			});
			assertThrows(BadUseSecuredTokenInvalidType.class, () -> {
				securedTokenService.loggedUserRightsExtractToken(token);
			});
		}

		@Test
		public void badUse_tokenTags() {
			final String token = generateJwts(jwt -> {
				jwt.claim("tags", makeRandomThing());
			});
			assertThrows(RequiredTypeException.class, () -> {
				securedTokenService.loggedUserRightsExtractToken(token);
			});
		}
	}

	@Test
	public void securedRedirectRequestGenerateToken() {
		final String token = securedTokenService.securedRedirectRequestGenerateToken(
		        makeUUID(), thirtyDays, makeRandomThing());
		assertNotNull(token);
	}

	@Nested
	class SecuredRedirectRequest {

		private String target;

		@BeforeEach
		public void init() {
			target = makeRandomThing();
		}

		@Test
		public void ok() throws NotAcceptableSecuredTokenException {
			final var uuid = makeUUID();
			final String token = securedTokenService.securedRedirectRequestGenerateToken(
			        uuid, thirtyDays, target);
			final var result = securedTokenService.securedRedirectRequestExtractToken(token, target);
			assertEquals(uuid, result);
		}

		@Test
		public void invalidEmpty() {
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.securedRedirectRequestExtractToken("", "");
			});
		}

		@Test
		public void invalidNull() {
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.securedRedirectRequestExtractToken(null, null);
			});
		}

		@Test
		public void invalidNotAJwt() {
			final var text = makeRandomThing();
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.securedRedirectRequestExtractToken(
				        text + "," + "text" + "," + text, makeRandomString());
			});
		}

		@Test
		public void expired() {
			final String token = securedTokenService.securedRedirectRequestGenerateToken(
			        makeUUID(), ZERO, makeRandomThing());
			assertThrows(ExpiredSecuredToken.class, () -> {
				securedTokenService.securedRedirectRequestExtractToken(token, makeRandomString());
			});
		}

		private String generateJwts(final Consumer<JwtBuilder> builder) {
			final var token = generateJwtsWithoutSign().signWith(Keys.hmacShaKeyFor(secret), HS512);
			builder.accept(token);
			return token.compact();
		}

		private JwtBuilder generateJwtsWithoutSign() {
			return Jwts.builder()
			        .setHeaderParam("typ", TOKEN_TYPE)
			        .setIssuer(TOKEN_ISSUER_SECUREDREQUEST + "/" + target)
			        .setAudience(TOKEN_AUDIENCE)
			        .setSubject(makeUUID())
			        .setExpiration(inThirtyDays);
		}

		@Test
		public void invalidUnsupported() {
			final String token = generateJwtsWithoutSign().compact();
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.securedRedirectRequestExtractToken(token, makeRandomString());
			});
		}

		@Test
		public void broken() {
			final byte[] secret = makeRandomBytes(256);
			final String token = generateJwtsWithoutSign().signWith(Keys.hmacShaKeyFor(secret), HS512).compact();
			assertThrows(BrokenSecuredToken.class, () -> {
				securedTokenService.securedRedirectRequestExtractToken(token, makeRandomString());
			});
		}

		@Test
		public void badUse_issuer() {
			final String token = generateJwts(jwt -> {
				jwt.setIssuer(makeRandomThing());
			});
			assertThrows(BadUseSecuredTokenInvalidIssuer.class, () -> {
				securedTokenService.securedRedirectRequestExtractToken(token, makeRandomString());
			});
		}

		@Test
		public void badUse_audience() {
			final String token = generateJwts(jwt -> {
				jwt.setAudience(makeRandomThing());
			});
			assertThrows(BadUseSecuredTokenInvalidAudience.class, () -> {
				securedTokenService.securedRedirectRequestExtractToken(token, target);
			});
		}

		@Test
		public void badUse_tokentype() {
			final String token = generateJwts(jwt -> {
				jwt.setHeaderParam("typ", makeRandomThing());
			});
			assertThrows(BadUseSecuredTokenInvalidType.class, () -> {
				securedTokenService.securedRedirectRequestExtractToken(token, makeRandomString());
			});
		}

		@Test
		public void badUse_tokenTargetName() {
			final String token = securedTokenService.securedRedirectRequestGenerateToken(
			        makeUUID(), thirtyDays, makeRandomString());
			assertThrows(BadUseSecuredTokenInvalidIssuer.class, () -> {
				securedTokenService.securedRedirectRequestExtractToken(token, makeRandomString());
			});
		}
	}

	@Test
	public void userFormCheckToken() {
		final String token = securedTokenService.userFormGenerateToken(makeRandomThing(), makeUUID(), thirtyDays);
		assertNotNull(token);
	}

	@Nested
	class UserFormCheckToken {

		@Test
		public void ok() throws NotAcceptableSecuredTokenException {
			final var uuid = makeUUID();
			final String token = securedTokenService.userFormGenerateToken(formName, uuid, thirtyDays);
			final var result = securedTokenService.userFormExtractTokenUUID(formName, token);
			assertEquals(uuid, result);
		}

		@Test
		public void invalidEmpty() {
			final String token = "";
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.userFormExtractTokenUUID(formName, token);
			});
		}

		@Test
		public void invalidNull() {
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.userFormExtractTokenUUID(formName, null);
			});
		}

		@Test
		public void invalidNotAJwt() {
			final var text = makeRandomThing();
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.userFormExtractTokenUUID(formName, text + "," + "text" + "," + text);
			});
		}

		@Test
		public void expired() {
			final var uuid = makeUUID();
			final String token = securedTokenService.userFormGenerateToken(formName, uuid, ZERO);
			assertThrows(ExpiredSecuredToken.class, () -> {
				securedTokenService.userFormExtractTokenUUID(formName, token);
			});
		}

		private String generateJwts(final Consumer<JwtBuilder> builder) {
			final var token = generateJwtsWithoutSign().signWith(Keys.hmacShaKeyFor(secret), HS512);
			builder.accept(token);
			return token.compact();
		}

		private JwtBuilder generateJwtsWithoutSign() {
			return Jwts.builder()
			        .setHeaderParam("typ", TOKEN_TYPE)
			        .setIssuer(TOKEN_ISSUER_FORM)
			        .setAudience(TOKEN_AUDIENCE)
			        .setSubject(makeUUID())
			        .setExpiration(inThirtyDays)
			        .claim("formname", formName);
		}

		@Test
		public void invalidUnsupported() {
			final String token = generateJwtsWithoutSign().compact();
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.userFormExtractTokenUUID(formName, token);
			});
		}

		@Test
		public void broken() {
			final byte[] secret = makeRandomBytes(256);
			final String token = generateJwtsWithoutSign().signWith(Keys.hmacShaKeyFor(secret), HS512).compact();
			assertThrows(BrokenSecuredToken.class, () -> {
				securedTokenService.userFormExtractTokenUUID(formName, token);
			});
		}

		@Test
		public void badUse_issuer() {
			final String token = generateJwts(jwt -> {
				jwt.setIssuer(makeRandomThing());
			});
			assertThrows(BadUseSecuredTokenInvalidIssuer.class, () -> {
				securedTokenService.userFormExtractTokenUUID(formName, token);
			});
		}

		@Test
		public void badUse_audience() {
			final String token = generateJwts(jwt -> {
				jwt.setAudience(makeRandomThing());
			});
			assertThrows(BadUseSecuredTokenInvalidAudience.class, () -> {
				securedTokenService.userFormExtractTokenUUID(formName, token);
			});
		}

		@Test
		public void badUse_tokentype() {
			final String token = generateJwts(jwt -> {
				jwt.setHeaderParam("typ", makeRandomThing());
			});
			assertThrows(BadUseSecuredTokenInvalidType.class, () -> {
				securedTokenService.userFormExtractTokenUUID(formName, token);
			});
		}

		@Test
		public void badUse_tokenformName() {
			final String token = generateJwts(jwt -> {
				jwt.claim("formname", makeRandomThing());
			});
			assertThrows(BadUseSecuredTokenInvalidForm.class, () -> {
				securedTokenService.userFormExtractTokenUUID(formName, token);
			});
		}
	}

	@Nested
	class SetupTOTP {

		private String uuid;
		private String totpSecret;
		private List<String> backupCodes;

		@BeforeEach
		public void init() {
			uuid = makeUUID();
			totpSecret = makeRandomThing();
			backupCodes = makeRandomThings().limit(6).collect(toUnmodifiableList());
		}

		@Test
		public void ok() throws NotAcceptableSecuredTokenException {
			final String token = securedTokenService.setupTOTPGenerateToken(uuid, thirtyDays, totpSecret, backupCodes);
			final var result = securedTokenService.setupTOTPExtractToken(token);
			assertEquals(uuid, result.getUserUUID());
			assertEquals(totpSecret, result.getSecret());
			assertEquals(backupCodes.size(), result.getBackupCodes().size());
		}

		@Test
		public void invalidEmpty() {
			final String token = "";
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.setupTOTPExtractToken(token);
			});
		}

		@Test
		public void invalidNull() {
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.setupTOTPExtractToken(null);
			});
		}

		@Test
		public void invalidNotAJwt() {
			final var text = makeRandomThing();
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.setupTOTPExtractToken(text + "," + "text" + "," + text);
			});
		}

		@Test
		public void expired() {
			final String token = securedTokenService.setupTOTPGenerateToken(uuid, ZERO, totpSecret, backupCodes);
			assertThrows(ExpiredSecuredToken.class, () -> {
				securedTokenService.setupTOTPExtractToken(token);
			});
		}

		private String generateJwts(final Consumer<JwtBuilder> builder) {
			final var token = generateJwtsWithoutSign().signWith(Keys.hmacShaKeyFor(secret), HS512);
			builder.accept(token);
			return token.compact();
		}

		private JwtBuilder generateJwtsWithoutSign() {
			return Jwts.builder()
			        .setHeaderParam("typ", TOKEN_TYPE)
			        .setIssuer(TOKEN_ISSUER_SETUPTOTP)
			        .setAudience(TOKEN_AUDIENCE)
			        .setSubject(makeUUID())
			        .setExpiration(inThirtyDays)
			        .claim("secret", totpSecret)
			        .claim("backupCodes", backupCodes);
		}

		@Test
		public void invalidUnsupported() {
			final String token = generateJwtsWithoutSign().compact();
			assertThrows(InvalidFormatSecuredToken.class, () -> {
				securedTokenService.setupTOTPExtractToken(token);
			});
		}

		@Test
		public void broken() {
			final byte[] secret = makeRandomBytes(256);
			final String token = generateJwtsWithoutSign().signWith(Keys.hmacShaKeyFor(secret), HS512).compact();
			assertThrows(BrokenSecuredToken.class, () -> {
				securedTokenService.setupTOTPExtractToken(token);
			});
		}

		@Test
		public void badUse_issuer() {
			final String token = generateJwts(jwt -> {
				jwt.setIssuer(makeRandomThing());
			});
			assertThrows(BadUseSecuredTokenInvalidIssuer.class, () -> {
				securedTokenService.setupTOTPExtractToken(token);
			});
		}

		@Test
		public void badUse_audience() {
			final String token = generateJwts(jwt -> {
				jwt.setAudience(makeRandomThing());
			});
			assertThrows(BadUseSecuredTokenInvalidAudience.class, () -> {
				securedTokenService.setupTOTPExtractToken(token);
			});
		}

		@Test
		public void badUse_tokentype() {
			final String token = generateJwts(jwt -> {
				jwt.setHeaderParam("typ", makeRandomThing());
			});
			assertThrows(BadUseSecuredTokenInvalidType.class, () -> {
				securedTokenService.setupTOTPExtractToken(token);
			});
		}
	}

}
