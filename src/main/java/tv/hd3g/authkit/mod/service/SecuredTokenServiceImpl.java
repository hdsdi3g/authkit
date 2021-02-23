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
import static java.util.stream.Collectors.toUnmodifiableSet;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import tv.hd3g.authkit.mod.dto.LoggedUserTagsTokenDto;
import tv.hd3g.authkit.mod.dto.SetupTOTPTokenDto;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException.BadUseSecuredTokenInvalidAudience;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException.BadUseSecuredTokenInvalidForm;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException.BadUseSecuredTokenInvalidIssuer;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException.BadUseSecuredTokenInvalidType;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException.BrokenSecuredToken;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException.ExpiredSecuredToken;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException.InvalidFormatSecuredToken;

@Service
public class SecuredTokenServiceImpl implements SecuredTokenService {

	private static Logger log = LogManager.getLogger();

	public static final String TOKEN_TYPE = "JWT";
	public static final String TOKEN_AUDIENCE = "authkit";
	public static final String TOKEN_ISSUER_FORM = "form";
	public static final String TOKEN_ISSUER_LOGIN = "loggedUser";
	public static final String TOKEN_ISSUER_SECUREDREQUEST = "UsrSecRq";
	public static final String TOKEN_ISSUER_SETUPTOTP = "setupTOTP";

	private static final String CLAIM_FORMNAME = "formname";

	private final byte[] secret;

	public SecuredTokenServiceImpl(@Value("${authkit.jwt_secret}") final String base64secret) {
		secret = Base64.getDecoder().decode(base64secret.getBytes());
	}

	@Override
	public String simpleFormGenerateToken(final String formName, final Duration expirationDuration) {
		final var now = System.currentTimeMillis();

		return Jwts.builder()
		        .signWith(Keys.hmacShaKeyFor(secret), HS512)
		        .setHeaderParam("typ", TOKEN_TYPE)
		        .setIssuer(TOKEN_ISSUER_FORM)
		        .setAudience(TOKEN_AUDIENCE)
		        // .setSubject("(none)")
		        .setExpiration(new Date(now + expirationDuration.toMillis()))
		        .claim(CLAIM_FORMNAME, formName)
		        .compact();
	}

	private Jws<Claims> extractToken(final String token,
	                                 final String expectedIssuer) throws NotAcceptableSecuredTokenException {
		try {
			final var parsedToken = Jwts.parserBuilder().setSigningKey(secret).build().parseClaimsJws(token);
			log.debug("Check token: {}", () -> parsedToken);

			final var type = parsedToken.getHeader().getType();
			if (TOKEN_TYPE.equals(type) == false) {
				log.warn("Invalid token type: {}", type);
				throw new BadUseSecuredTokenInvalidType(type, TOKEN_TYPE);
			}
			final var claims = parsedToken.getBody();
			if (expectedIssuer != null) {
				final var issuer = claims.getIssuer();
				if (expectedIssuer.equals(issuer) == false) {
					log.warn("Invalid token issuer: {}", issuer);
					throw new BadUseSecuredTokenInvalidIssuer(issuer, expectedIssuer);
				}
			}
			final var audience = claims.getAudience();
			if (TOKEN_AUDIENCE.equals(audience) == false) {
				log.warn("Invalid token audience: {}", audience);
				throw new BadUseSecuredTokenInvalidAudience(audience, TOKEN_AUDIENCE);
			}
			return parsedToken;
		} catch (final ExpiredJwtException exception) {
			log.warn("Parse expired JWT: {}", exception.getMessage());
			throw new ExpiredSecuredToken();
		} catch (final UnsupportedJwtException exception) {
			log.warn("Parse unsupported JWT: {}", exception.getMessage());
			throw new InvalidFormatSecuredToken();
		} catch (final MalformedJwtException exception) {
			log.warn("Parse invalid JWT: {}", exception.getMessage());
			throw new InvalidFormatSecuredToken();
		} catch (final SignatureException exception) {
			log.warn("Parse JWT with invalid signature: {}", exception.getMessage());
			throw new BrokenSecuredToken();
		} catch (final IllegalArgumentException exception) {
			log.warn("Parse empty or null JWT: {}", exception.getMessage());
			throw new InvalidFormatSecuredToken();
		}
	}

	@Override
	public void simpleFormCheckToken(final String expectedFormName,
	                                 final String token) throws NotAcceptableSecuredTokenException {
		final var parsedToken = extractToken(token, TOKEN_ISSUER_FORM);
		final var claims = parsedToken.getBody();
		final var tokenformName = claims.get(CLAIM_FORMNAME, String.class);
		if (expectedFormName.equals(tokenformName) == false) {
			log.warn("Invalid token form: {}", tokenformName);
			throw new BadUseSecuredTokenInvalidForm(tokenformName, TOKEN_ISSUER_FORM);
		}
	}

	@Override
	public String loggedUserRightsGenerateToken(final String userUUID,
	                                            final Duration expirationDuration,
	                                            final Set<String> tags,
	                                            final String onlyForHost) {
		final var now = System.currentTimeMillis();

		return Jwts.builder()
		        .signWith(Keys.hmacShaKeyFor(secret), HS512)
		        .setHeaderParam("typ", TOKEN_TYPE)
		        .setIssuer(TOKEN_ISSUER_LOGIN)
		        .setAudience(TOKEN_AUDIENCE)
		        .setSubject(userUUID)
		        .setExpiration(new Date(now + expirationDuration.toMillis()))
		        .claim("tags", tags)
		        .claim("host", onlyForHost)
		        .compact();
	}

	@Override
	public LoggedUserTagsTokenDto loggedUserRightsExtractToken(final String token,
	                                                           final boolean fromCookie) throws NotAcceptableSecuredTokenException {
		final var claims = extractToken(token, TOKEN_ISSUER_LOGIN).getBody();
		final ArrayList<?> rawTags = claims.get("tags", ArrayList.class);
		final String host;
		if (claims.containsKey("host")) {
			host = claims.get("host", String.class);
		} else {
			host = null;
		}
		final var stringTags = rawTags.stream().map(d2 -> (String) d2).collect(toUnmodifiableSet());// NOSONAR S1612
		return new LoggedUserTagsTokenDto(claims.getSubject(), stringTags, claims.getExpiration(), fromCookie, host);
	}

	@Override
	public String securedRedirectRequestGenerateToken(final String userUUID,
	                                                  final Duration expirationDuration,
	                                                  final String target) {
		final var now = System.currentTimeMillis();
		return Jwts.builder()
		        .signWith(Keys.hmacShaKeyFor(secret), HS512)
		        .setHeaderParam("typ", TOKEN_TYPE)
		        .setIssuer(TOKEN_ISSUER_SECUREDREQUEST + "/" + target)
		        .setAudience(TOKEN_AUDIENCE)
		        .setSubject(userUUID)
		        .setExpiration(new Date(now + expirationDuration.toMillis()))
		        .compact();
	}

	@Override
	public String securedRedirectRequestExtractToken(final String token,
	                                                 final String expectedTarget) throws NotAcceptableSecuredTokenException {
		return extractToken(token, TOKEN_ISSUER_SECUREDREQUEST + "/" + expectedTarget).getBody().getSubject();
	}

	@Override
	public String userFormGenerateToken(final String formName,
	                                    final String userUUID,
	                                    final Duration expirationDuration) {
		final var now = System.currentTimeMillis();

		return Jwts.builder()
		        .signWith(Keys.hmacShaKeyFor(secret), HS512)
		        .setHeaderParam("typ", TOKEN_TYPE)
		        .setIssuer(TOKEN_ISSUER_FORM)
		        .setAudience(TOKEN_AUDIENCE)
		        .setSubject(userUUID)
		        .setExpiration(new Date(now + expirationDuration.toMillis()))
		        .claim(CLAIM_FORMNAME, formName)
		        .compact();
	}

	@Override
	public String userFormExtractTokenUUID(final String formName,
	                                       final String securetoken) throws NotAcceptableSecuredTokenException {
		final var claims = extractToken(securetoken, TOKEN_ISSUER_FORM).getBody();
		final var expectedFormName = claims.get(CLAIM_FORMNAME, String.class);
		if (formName.equals(expectedFormName) == false) {
			log.warn("Invalid token form: {}", formName);
			throw new BadUseSecuredTokenInvalidForm(formName, TOKEN_ISSUER_FORM);
		}
		return claims.getSubject();
	}

	@Override
	public String setupTOTPGenerateToken(final String userUUID,
	                                     final Duration expirationDuration,
	                                     final String secret,
	                                     final List<String> backupCodes) {
		final var now = System.currentTimeMillis();

		return Jwts.builder()
		        .signWith(Keys.hmacShaKeyFor(this.secret), HS512)
		        .setHeaderParam("typ", TOKEN_TYPE)
		        .setIssuer(TOKEN_ISSUER_SETUPTOTP)
		        .setAudience(TOKEN_AUDIENCE)
		        .setSubject(userUUID)
		        .setExpiration(new Date(now + expirationDuration.toMillis()))
		        .claim("secret", secret)
		        .claim("backupCodes", backupCodes)
		        .compact();
	}

	@Override
	public SetupTOTPTokenDto setupTOTPExtractToken(final String token) throws NotAcceptableSecuredTokenException {
		final var claims = extractToken(token, TOKEN_ISSUER_SETUPTOTP).getBody();
		final ArrayList<?> rawBackupCodes = claims.get("backupCodes", ArrayList.class);
		final var backupCodes = rawBackupCodes.stream().map(d2 -> (String) d2).collect(toUnmodifiableSet()); // NOSONAR S1612
		return new SetupTOTPTokenDto(claims.getSubject(), claims.get("secret", String.class), backupCodes);
	}

}
