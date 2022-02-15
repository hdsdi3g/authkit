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
package tv.hd3g.authkit.mod.exception;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.only;
import static org.mockito.Mockito.verify;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;

import tv.hd3g.authkit.mod.service.AuditReportService;
import tv.hd3g.authkit.tool.DataGenerator;

class SecurityRejectedRequestExceptionTest {

	@Mock
	AuditReportService auditService;
	@Mock
	HttpServletRequest request;

	String logMessage;
	UUID userUUID;

	SecurityRejectedRequestException s;

	@BeforeEach
	void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		logMessage = DataGenerator.makeRandomString();
		userUUID = UUID.randomUUID();
	}

	@AfterEach
	void end() {
		Mockito.verifyNoMoreInteractions(auditService, request);
	}

	abstract class BaseTest {// NOSONAR S7590

		abstract SecurityRejectedRequestException provide();

		abstract void afterPushAudit();

		abstract HttpStatus assertStatus();

		@BeforeEach
		void init() throws Exception {
			s = provide();
		}

		@Test
		void testPushAudit() {// NOSONAR S2699
			s.pushAudit(auditService, request);
			afterPushAudit();
		}

		@Test
		void testGetStatusCode() {
			assertEquals(assertStatus(), s.getStatusCode());
		}

		@Test
		void testGetUserUUID() {
			assertEquals(userUUID, s.getUserUUID());
		}

		@Test
		void testGetMessage() {
			assertEquals(logMessage, s.getMessage());
		}

		@Test
		void testGetCause() {
			assertNull(s.getCause());
		}
	}

	@Nested
	class UnauthorizedRequestException_WithUserTest extends BaseTest {

		@Override
		SecurityRejectedRequestException provide() {
			return new UnauthorizedRequestException(logMessage, userUUID.toString());
		}

		@Override
		void afterPushAudit() {
			verify(auditService, only()).interceptUnauthorizedRequest(request);
		}

		@Override
		HttpStatus assertStatus() {
			return UNAUTHORIZED;
		}

	}

	@Nested
	class UnauthorizedRequestException_WOUserTest extends BaseTest {

		@Override
		SecurityRejectedRequestException provide() {
			return new UnauthorizedRequestException(logMessage);
		}

		@Override
		void afterPushAudit() {
			verify(auditService, only()).interceptUnauthorizedRequest(request);
		}

		@Override
		HttpStatus assertStatus() {
			return UNAUTHORIZED;
		}

		@Override
		void testGetUserUUID() {
		}
	}

	@Nested
	class ForbiddenRequestExceptionTest extends BaseTest {

		@Override
		SecurityRejectedRequestException provide() {
			return new ForbiddenRequestException(logMessage, userUUID.toString());
		}

		@Override
		void afterPushAudit() {
			verify(auditService, only()).interceptForbiddenRequest(request);
		}

		@Override
		HttpStatus assertStatus() {
			return FORBIDDEN;
		}

	}

	@Nested
	class BadRequestExceptionTest extends BaseTest {

		@Override
		SecurityRejectedRequestException provide() {
			return new BadRequestException(logMessage);
		}

		@Override
		void afterPushAudit() {
		}

		@Override
		HttpStatus assertStatus() {
			return BAD_REQUEST;
		}

		@Override
		void testGetUserUUID() {
		}
	}

}
