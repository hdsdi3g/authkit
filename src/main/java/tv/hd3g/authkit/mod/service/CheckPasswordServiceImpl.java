/*
 * This file is part of authkit.
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
 * Copyright (C) hdsdi3g for hd3g.tv 2021
 *
 */
package tv.hd3g.authkit.mod.service;

import static tv.hd3g.authkit.mod.service.AuditReportService.RejectLoginCause.EMPTY_PASSWORD;
import static tv.hd3g.authkit.mod.service.AuditReportService.RejectLoginCause.INVALID_PASSWORD;
import static tv.hd3g.authkit.mod.service.AuditReportService.RejectLoginCause.MISSING_PASSWORD;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import tv.hd3g.authkit.mod.dto.Password;
import tv.hd3g.authkit.mod.entity.Credential;
import tv.hd3g.authkit.mod.exception.UserCantLoginException;
import tv.hd3g.authkit.mod.service.AuditReportService.RejectLoginCause;

@Service
public class CheckPasswordServiceImpl implements CheckPasswordService {
	private static final Argon2 ARGON2 = Argon2Factory.create();

	@Autowired
	private ExternalAuthClientService externalAuthClientService;
	@Autowired
	private CipherService cipherService;

	@Override
	public Optional<RejectLoginCause> checkPassword(final Password userEnterPassword, final Credential credential) {
		if (userEnterPassword == null) {
			return Optional.ofNullable(MISSING_PASSWORD);
		} else if (userEnterPassword.length() == 0) {
			return Optional.ofNullable(EMPTY_PASSWORD);
		} else if (credential.getLdapdomain() != null) {
			try {
				externalAuthClientService.logonUser(credential.getLogin(), userEnterPassword, credential
				        .getLdapdomain());
			} catch (final UserCantLoginException e) {
				return Optional.ofNullable(INVALID_PASSWORD);
			}
		} else {
			final var passwordHash = cipherService.unCipherToString(credential.getPasswordhash());
			if (userEnterPassword.verify(ARGON2, passwordHash) == false) {
				return Optional.ofNullable(INVALID_PASSWORD);
			}
		}
		return Optional.empty();
	}
}
