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

import java.time.Duration;
import java.util.List;
import java.util.Set;

import tv.hd3g.authkit.mod.dto.LoggedUserTagsTokenDto;
import tv.hd3g.authkit.mod.dto.SetupTOTPTokenDto;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException;

public interface SecuredTokenService {

	/**
	 * Generate a secured token for an html classic form.
	 * @return raw token
	 */
	String simpleFormGenerateToken(String formName, Duration expirationDuration);

	/**
	 * Checked status
	 */
	void simpleFormCheckToken(String expectedFormName, String token) throws NotAcceptableSecuredTokenException;

	/**
	 * Generate a secured token after user login correctly.
	 * @return raw token
	 */
	String loggedUserRightsGenerateToken(String userUUID,
	                                     Duration expirationDuration,
	                                     Set<String> tags,
	                                     String onlyForHost);

	/**
	 * Checked user tags
	 */
	LoggedUserTagsTokenDto loggedUserRightsExtractToken(final String token,
	                                                    boolean fromCookie) throws NotAcceptableSecuredTokenException;

	/**
	 * Generate a secured token for user connection-less operations.
	 * @return raw token
	 */
	String securedRedirectRequestGenerateToken(final String userUUID,
	                                           final Duration expirationDuration,
	                                           final String target);

	/**
	 * @return User UUID
	 */
	String securedRedirectRequestExtractToken(String token,
	                                          String expectedTarget) throws NotAcceptableSecuredTokenException;

	/**
	 * Generate a secured token limited to an user for an html classic form.
	 * @return raw token
	 */
	String userFormGenerateToken(String formName, String userUUID, Duration expirationDuration);

	/**
	 * @return User UUID provided by generateUserForm
	 */
	String userFormExtractTokenUUID(String formName, String securetoken) throws NotAcceptableSecuredTokenException;

	String setupTOTPGenerateToken(String userUUID,
	                              final Duration expirationDuration,
	                              String secret,
	                              List<String> backupCodes);

	SetupTOTPTokenDto setupTOTPExtractToken(final String token) throws NotAcceptableSecuredTokenException;
}
