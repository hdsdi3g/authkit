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
package tv.hd3g.authkit.mod;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.internal.verification.VerificationModeFactory.atLeast;
import static tv.hd3g.authkit.mod.ControllerInterceptor.CONTROLLER_TYPE_ATTRIBUTE_NAME;
import static tv.hd3g.authkit.mod.ControllerInterceptor.USER_TOKEN_ATTRIBUTE_NAME;
import static tv.hd3g.authkit.utility.ControllerType.CLASSIC;
import static tv.hd3g.authkit.utility.ControllerType.REST;

import java.io.IOException;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;

import tv.hd3g.authkit.mod.exception.SecurityRejectedRequestException;
import tv.hd3g.authkit.mod.service.AuditReportService;
import tv.hd3g.authkit.tool.DataGenerator;

class SecurityRejectedRequestMappingExceptionResolverTest {

	@Mock
	AuditReportService auditService;
	@Mock
	HttpServletRequest request;
	@Mock
	HttpServletResponse response;
	@Mock
	Object handler;
	@Mock
	SecurityRejectedRequestException requestException;

	@Value("${authkit.auth-error-view:auth-error}")
	private String authErrorViewName;

	HttpStatus statusCode;
	UUID userUUID;
	String requestURL;

	SecurityRejectedRequestMappingExceptionResolver s;

	@BeforeEach
	void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		userUUID = UUID.randomUUID();
		DataGenerator.setupMock(request, true, userUUID.toString());
		requestURL = DataGenerator.makeRandomThing();
		statusCode = DataGenerator.getRandomEnum(HttpStatus.class);
		s = new SecurityRejectedRequestMappingExceptionResolver(auditService, authErrorViewName);
	}

	@AfterEach
	void end() {
		Mockito.verifyNoMoreInteractions(auditService,
		        request,
		        response,
		        handler,
		        requestException);
	}

	@Test
	void testDoResolveException_noREST_withControllerType_withUUID_errorIsSecurityRejected() {
		when(request.getAttribute(eq(CONTROLLER_TYPE_ATTRIBUTE_NAME))).thenReturn(CLASSIC);
		when(request.getRequestURL()).thenReturn(new StringBuffer(requestURL));
		when(requestException.getStatusCode()).thenReturn(statusCode);
		when(requestException.getUserUUID()).thenReturn(userUUID);

		final var mav = s.doResolveException(request, response, handler, requestException);
		assertNotNull(mav);
		assertEquals(authErrorViewName, mav.getViewName());
		final var model = mav.getModel();
		assertEquals(statusCode.value(), model.get("cause"));
		assertEquals(requestURL, model.get("requestURL"));
		assertTrue((boolean) model.get("isnotlogged"));

		verify(request, atLeastOnce()).getAttribute(eq(CONTROLLER_TYPE_ATTRIBUTE_NAME));
		verify(request, atLeastOnce()).getAttribute(eq(USER_TOKEN_ATTRIBUTE_NAME));
		verify(request, atLeastOnce()).getRequestURL();
		verify(request, atLeastOnce()).getRequestURI();
		verify(request, atLeastOnce()).getRemoteAddr();
		verify(request, atLeastOnce()).getHeader(eq("X-Forwarded-For"));
		verify(requestException, atLeastOnce()).getMessage();
		verify(requestException, atLeastOnce()).getStatusCode();
		verify(requestException, atLeastOnce()).getUserUUID();
		verify(requestException, times(1)).pushAudit(eq(auditService), eq(request));
	}

	@Test
	void testDoResolveException_withoutControllerType() {
		when(request.getAttribute(eq(CONTROLLER_TYPE_ATTRIBUTE_NAME))).thenReturn(null);

		final var mav = s.doResolveException(request, response, handler, requestException);
		assertNull(mav);

		verify(request, atLeastOnce()).getAttribute(eq(CONTROLLER_TYPE_ATTRIBUTE_NAME));
		verify(request, atLeast(0)).getRequestURI();
	}

	@Test
	void testDoResolveException_genericError() {
		when(request.getAttribute(eq(CONTROLLER_TYPE_ATTRIBUTE_NAME))).thenReturn(CLASSIC);
		final var mav = s.doResolveException(request, response, handler, new Exception());
		assertNull(mav);

		verify(request, atLeastOnce()).getAttribute(eq(CONTROLLER_TYPE_ATTRIBUTE_NAME));
		verify(request, atLeast(0)).getRequestURI();
	}

	@Test
	void testDoResolveException_noREST_withControllerType_withoutUUID_errorIsSecurityRejected() {
		when(request.getAttribute(eq(CONTROLLER_TYPE_ATTRIBUTE_NAME))).thenReturn(CLASSIC);
		when(request.getRequestURL()).thenReturn(new StringBuffer(requestURL));
		when(requestException.getStatusCode()).thenReturn(statusCode);

		final var mav = s.doResolveException(request, response, handler, requestException);
		assertNotNull(mav);
		assertEquals(authErrorViewName, mav.getViewName());
		final var model = mav.getModel();
		assertEquals(statusCode.value(), model.get("cause"));
		assertEquals(requestURL, model.get("requestURL"));
		assertTrue((boolean) model.get("isnotlogged"));

		verify(request, atLeastOnce()).getAttribute(eq(CONTROLLER_TYPE_ATTRIBUTE_NAME));
		verify(request, atLeastOnce()).getAttribute(eq(USER_TOKEN_ATTRIBUTE_NAME));
		verify(request, atLeastOnce()).getRequestURL();
		verify(request, atLeastOnce()).getRequestURI();
		verify(request, atLeastOnce()).getRemoteAddr();
		verify(request, atLeastOnce()).getHeader(eq("X-Forwarded-For"));
		verify(requestException, atLeastOnce()).getMessage();
		verify(requestException, atLeastOnce()).getStatusCode();
		verify(requestException, atLeastOnce()).getUserUUID();
		verify(requestException, times(1)).pushAudit(eq(auditService), eq(request));
	}

	@Test
	void testDoResolveException_REST_withControllerType_withUUID_errorIsSecurityRejected() throws IOException {
		when(request.getAttribute(eq(CONTROLLER_TYPE_ATTRIBUTE_NAME))).thenReturn(REST);
		when(request.getRequestURL()).thenReturn(new StringBuffer(requestURL));
		when(requestException.getStatusCode()).thenReturn(statusCode);
		when(requestException.getUserUUID()).thenReturn(userUUID);

		final var mav = s.doResolveException(request, response, handler, requestException);
		assertNotNull(mav);
		assertNull(mav.getViewName());
		assertEquals(0, mav.getModel().size());

		verify(request, atLeastOnce()).getAttribute(eq(CONTROLLER_TYPE_ATTRIBUTE_NAME));
		verify(request, atLeastOnce()).getRequestURI();
		verify(request, atLeastOnce()).getRemoteAddr();
		verify(request, atLeastOnce()).getHeader(eq("X-Forwarded-For"));
		verify(requestException, atLeastOnce()).getMessage();
		verify(requestException, atLeastOnce()).getStatusCode();
		verify(requestException, atLeastOnce()).getUserUUID();
		verify(requestException, times(1)).pushAudit(eq(auditService), eq(request));
		verify(response, times(1)).sendError(eq(statusCode.value()));
	}
}
