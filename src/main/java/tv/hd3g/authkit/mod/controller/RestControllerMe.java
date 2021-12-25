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

import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static org.owasp.encoder.Encode.forJavaScript;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import tv.hd3g.authkit.mod.ControllerInterceptor;
import tv.hd3g.authkit.mod.dto.ressource.IsExternalAuthDto;
import tv.hd3g.authkit.mod.dto.ressource.IsTOTPEnabledDto;
import tv.hd3g.authkit.mod.dto.ressource.SetupTOTPDto;
import tv.hd3g.authkit.mod.dto.ressource.UserPrivacyDto;
import tv.hd3g.authkit.mod.dto.validated.ChangeMyPasswordDto;
import tv.hd3g.authkit.mod.dto.validated.ValidationSetupTOTPDto;
import tv.hd3g.authkit.mod.dto.validated.ValidationTOTPDto;
import tv.hd3g.authkit.mod.entity.Credential;
import tv.hd3g.authkit.mod.exception.AuthKitException;
import tv.hd3g.authkit.mod.exception.BlockedUserException;
import tv.hd3g.authkit.mod.exception.ResetWithSamePasswordException;
import tv.hd3g.authkit.mod.repository.CredentialRepository;
import tv.hd3g.authkit.mod.service.AuthenticationService;
import tv.hd3g.authkit.mod.service.SecuredTokenService;
import tv.hd3g.authkit.mod.service.TOTPService;
import tv.hd3g.commons.authkit.AuditAfter;

@RestController
@RequestMapping(value = "/v1/authkit/me", produces = APPLICATION_JSON_VALUE)
public class RestControllerMe {

	@Autowired
	private AuthenticationService authenticationService;
	@Autowired
	private CredentialRepository credentialRepository;
	@Autowired
	private TOTPService totpService;
	@Autowired
	private SecuredTokenService securedTokenService;

	@Value("${authkit.maxTOTPSetupTime:20m}")
	private Duration expirationDuration;

	private String getCurrentUserUUID(final HttpServletRequest request) {
		return ControllerInterceptor.getRequestUserUUID(request).orElseThrow(
		        () -> new AuthKitException(SC_UNAUTHORIZED, "You must be connected before."));
	}

	private Credential getCurrentUserCredential(final String userUUID) {
		return Optional.ofNullable(credentialRepository.getByUserUUID(userUUID)).orElseThrow(
		        () -> new AuthKitException(SC_UNAUTHORIZED, "Can't found you're user account."));
	}

	@Transactional(readOnly = false)
	@PostMapping(value = "chpasswd")
	@AuditAfter(value = "changeMyPassword", changeSecurity = true)
	public ResponseEntity<Object> changeMyPassword(@RequestBody @Validated final ChangeMyPasswordDto chPasswordDto,
	                                               final HttpServletRequest request) {
		final var userUUID = getCurrentUserUUID(request);
		final var credential = getCurrentUserCredential(userUUID);
		if (credential.getLdapdomain() != null) {
			throw new AuthKitException("You can't change the password here for an external authentication");
		}
		final var checkResultFail = authenticationService.checkPassword(chPasswordDto.getCurrentpassword(), credential);
		if (checkResultFail.isPresent()) {
			throw new AuthKitException("Actual provided password is invalid: " + checkResultFail.get());
		} else if (credential.getTotpkey() != null) {
			authenticationService.checkCodeAndPassword(credential, chPasswordDto);
		}
		try {
			authenticationService.changeUserPassword(userUUID, chPasswordDto.getNewpassword());
		} catch (final ResetWithSamePasswordException e) {
			throw new AuthKitException("You can't change a password with the same");
		} catch (final BlockedUserException e) {
			throw new AuthKitException("You can't change the password for a blocked account");
		}
		return new ResponseEntity<>(OK);
	}

	@Transactional(readOnly = true)
	@GetMapping(value = "is-external-auth")
	public ResponseEntity<IsExternalAuthDto> isExternalAuth(final HttpServletRequest request) {
		final var userUUID = getCurrentUserUUID(request);
		final var credential = getCurrentUserCredential(userUUID);
		final var result = new IsExternalAuthDto(credential);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = true)
	@GetMapping(value = "set2auth")
	public ResponseEntity<SetupTOTPDto> prepareTOTP(final HttpServletRequest request) {
		final var userUUID = getCurrentUserUUID(request);
		final var credential = getCurrentUserCredential(userUUID);
		if (credential.getTotpkey() != null) {
			throw new AuthKitException("2auth was previouly setup: please cancel it before setup a second time.");
		}

		final var secret = totpService.makeSecret();
		final var totpURI = totpService.makeURI(secret, credential.getUser(), forJavaScript(request.getServerName()));
		final var qrcode = totpService.makeQRCode(totpURI);
		final var backupCodes = totpService.makeBackupCodes();
		final var jwtControl = securedTokenService.setupTOTPGenerateToken(
		        userUUID, expirationDuration, secret, backupCodes);

		final var result = new SetupTOTPDto(secret, totpURI, qrcode, backupCodes, jwtControl);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@PostMapping(value = "set2auth")
	@AuditAfter(value = "setTOTP", changeSecurity = true)
	public ResponseEntity<Object> confirmTOTP(@RequestBody @Validated final ValidationSetupTOTPDto setupDto,
	                                          final HttpServletRequest request) {
		final var userUUID = getCurrentUserUUID(request);
		final var credential = getCurrentUserCredential(userUUID);
		if (credential.getTotpkey() != null) {
			throw new AuthKitException("2auth was previouly setup: please cancel it before setup a second time.");
		}
		authenticationService.setupTOTPWithChecks(setupDto, userUUID);
		return new ResponseEntity<>(OK);
	}

	@Transactional(readOnly = true)
	@GetMapping(value = "has2auth")
	public ResponseEntity<IsTOTPEnabledDto> hasATOTP(final HttpServletRequest request) {
		final var userUUID = getCurrentUserUUID(request);
		final var credential = getCurrentUserCredential(userUUID);
		final var result = new IsTOTPEnabledDto(credential);
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@DeleteMapping(value = "set2auth")
	@AuditAfter(value = "setTOTP", changeSecurity = true)
	public ResponseEntity<Object> removeTOTP(@RequestBody @Validated final ValidationTOTPDto validationDto,
	                                         final HttpServletRequest request) {
		final var userUUID = getCurrentUserUUID(request);
		final var credential = getCurrentUserCredential(userUUID);
		if (credential.getTotpkey() == null) {
			throw new AuthKitException("2auth was not setup.");
		}
		authenticationService.checkCodeAndPassword(credential, validationDto);
		totpService.removeTOTP(credential);
		return new ResponseEntity<>(OK);
	}

	@Transactional(readOnly = true)
	@GetMapping(value = "privacy")
	@AuditAfter(value = "getPrivacy", changeSecurity = false)
	public ResponseEntity<UserPrivacyDto> getPrivacy(final HttpServletRequest request) {
		final var userUUID = getCurrentUserUUID(request);
		final var list = authenticationService.getUserPrivacyList(List.of(userUUID));
		UserPrivacyDto result;
		if (list.isEmpty()) {
			result = new UserPrivacyDto();
		} else {
			result = list.get(0);
		}
		return new ResponseEntity<>(result, OK);
	}

	@Transactional(readOnly = false)
	@PutMapping(value = "privacy")
	@AuditAfter(value = "setPrivacy", changeSecurity = true)
	public ResponseEntity<Object> setPrivacy(@RequestBody @Validated final UserPrivacyDto userPrivacyDto,
	                                         final HttpServletRequest request) {
		final var userUUID = getCurrentUserUUID(request);
		authenticationService.setUserPrivacy(userUUID, userPrivacyDto);
		return new ResponseEntity<>(OK);
	}

}
