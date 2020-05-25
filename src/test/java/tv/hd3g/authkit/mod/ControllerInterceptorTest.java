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
package tv.hd3g.authkit.mod;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static tv.hd3g.authkit.mod.ControllerInterceptor.USER_UUID_ATTRIBUTE_NAME;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomIPv4;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomString;
import static tv.hd3g.authkit.tool.DataGenerator.makeUUID;

import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.resource.ResourceHttpRequestHandler;

import tv.hd3g.authkit.dummy.ControllerAudit;
import tv.hd3g.authkit.dummy.ControllerClassRequireRenforceCheck;
import tv.hd3g.authkit.dummy.ControllerMethodRequireRenforceCheck;
import tv.hd3g.authkit.dummy.ControllerWithSecure;
import tv.hd3g.authkit.dummy.ControllerWithoutSecure;
import tv.hd3g.authkit.mod.component.EndpointsListener;
import tv.hd3g.authkit.mod.dto.LoggedUserTagsTokenDto;
import tv.hd3g.authkit.mod.repository.UserRepository;
import tv.hd3g.authkit.mod.service.AuditReportService;
import tv.hd3g.authkit.mod.service.AuthenticationService;
import tv.hd3g.authkit.mod.service.SecuredTokenService;
import tv.hd3g.authkit.tool.DataGenerator;

public class ControllerInterceptorTest {

	@Mock
	private AuditReportService auditService;
	@Mock
	private SecuredTokenService securedTokenService;
	@Mock
	private HttpServletRequest request;
	@Mock
	private HttpServletResponse response;
	@Mock
	private HandlerMethod handlerMethod;
	@Mock
	private Exception exception;
	@Mock
	private UserRepository userRepository;
	@Mock
	private AuthenticationService authenticationService;

	private EndpointsListener endpointsListener;
	private ControllerInterceptor controlerInterceptor;
	private String uuid;

	@BeforeEach
	public void init() {
		MockitoAnnotations.initMocks(this);
		DataGenerator.setupMock(request);
		endpointsListener = new EndpointsListener();
		controlerInterceptor = new ControllerInterceptor(
		        auditService, securedTokenService, endpointsListener, authenticationService);
		uuid = makeUUID();
		when(request.getAttribute(eq(USER_UUID_ATTRIBUTE_NAME))).then(i -> uuid);
	}

	@Test
	public void preHandleUserNotLogged_CtrlWithoutSecure_verbWithoutSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithoutSecure.class);
		when(handlerMethod.getMethod()).then(i -> ControllerWithoutSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		assertTrue(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(response, never()).reset();
		verify(response, never()).sendError(ArgumentMatchers.anyInt());

		verify(auditService, never()).interceptForbiddenRequest(request);
		verify(auditService, never()).interceptUnauthorizedRequest(request);
		verify(auditService, never()).onChangeSecurity(request, null);
		verify(auditService, never()).onImportantError(request, null, null);
		verify(auditService, never()).onSimpleEvent(request, null);
		verify(auditService, never()).onUseSecurity(request, null);
		verify(auditService, never()).onRejectLogin(request, null, null, null);
		verify(auditService, never()).onLogin(request, null, null);
	}

	@Test
	public void preHandleUserNotLogged_CtrlWithoutSecure_verbWithSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithoutSecure.class);
		when(handlerMethod.getMethod()).then(i -> ControllerWithoutSecure.class.getMethod("verbWithSecure"));
		when(request.getMethod()).thenReturn("GET");

		assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(response, atLeastOnce()).reset();
		verify(response, atLeastOnce()).sendError(UNAUTHORIZED.value());

		verify(auditService, never()).interceptForbiddenRequest(request);
		verify(auditService, atLeastOnce()).interceptUnauthorizedRequest(request);
		verify(auditService, never()).onChangeSecurity(request, null);
		verify(auditService, never()).onImportantError(request, null, null);
		verify(auditService, never()).onSimpleEvent(request, null);
		verify(auditService, never()).onUseSecurity(request, null);
		verify(auditService, never()).onRejectLogin(request, null, null, null);
		verify(auditService, never()).onLogin(request, null, null);
	}

	@Test
	public void preHandleUserNotLogged_CtrlWithSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithSecure.class);
		when(handlerMethod.getMethod()).then(i -> ControllerWithSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(response, atLeastOnce()).reset();
		verify(response, atLeastOnce()).sendError(UNAUTHORIZED.value());

		verify(auditService, never()).interceptForbiddenRequest(request);
		verify(auditService, atLeastOnce()).interceptUnauthorizedRequest(request);
		verify(auditService, never()).onChangeSecurity(request, null);
		verify(auditService, never()).onImportantError(request, null, null);
		verify(auditService, never()).onSimpleEvent(request, null);
		verify(auditService, never()).onUseSecurity(request, null);
		verify(auditService, never()).onRejectLogin(request, null, null, null);
		verify(auditService, never()).onLogin(request, null, null);
	}

	@Test
	public void afterCompletionAudit_NoAudit() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithoutSecure.class);
		when(handlerMethod.getMethod()).then(i -> ControllerWithoutSecure.class.getMethod("verbWithoutSecure"));

		controlerInterceptor.afterCompletion(request, response, handlerMethod, exception);
		verify(auditService, never()).interceptForbiddenRequest(request);
		verify(auditService, never()).interceptUnauthorizedRequest(request);
		verify(auditService, never()).onChangeSecurity(request, null);
		verify(auditService, never()).onImportantError(request, null, null);
		verify(auditService, never()).onSimpleEvent(request, null);
		verify(auditService, never()).onUseSecurity(request, null);
		verify(auditService, never()).onRejectLogin(request, null, null, null);
		verify(auditService, never()).onLogin(request, null, null);
	}

	@Test
	public void afterCompletionAudit_verbUseSecurity() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerAudit.class);
		when(handlerMethod.getMethod()).then(i -> ControllerAudit.class.getMethod("verbUseSecurity"));

		controlerInterceptor.afterCompletion(request, response, handlerMethod, exception);
		verify(auditService, never()).interceptForbiddenRequest(request);
		verify(auditService, never()).interceptUnauthorizedRequest(request);
		verify(auditService, never()).onChangeSecurity(request, null);
		verify(auditService, never()).onImportantError(request, null, null);
		verify(auditService, atLeastOnce()).onSimpleEvent(request, List.of("OnClass"));
		verify(auditService, atLeastOnce()).onUseSecurity(request, List.of("useSecurity"));
		verify(auditService, never()).onRejectLogin(request, null, null, null);
		verify(auditService, never()).onLogin(request, null, null);
	}

	@Test
	public void afterCompletionAudit_verbChangeSecurity() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerAudit.class);
		when(handlerMethod.getMethod()).then(i -> ControllerAudit.class.getMethod("verbChangeSecurity"));

		controlerInterceptor.afterCompletion(request, response, handlerMethod, exception);
		verify(auditService, never()).interceptForbiddenRequest(request);
		verify(auditService, never()).interceptUnauthorizedRequest(request);
		verify(auditService, atLeastOnce()).onChangeSecurity(request, List.of("changeSecurity"));
		verify(auditService, never()).onImportantError(request, null, null);
		verify(auditService, atLeastOnce()).onSimpleEvent(request, List.of("OnClass"));
		verify(auditService, never()).onUseSecurity(request, null);
		verify(auditService, never()).onRejectLogin(request, null, null, null);
		verify(auditService, never()).onLogin(request, null, null);
	}

	@Test
	public void afterCompletionAudit_verbCantDoErrors() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerAudit.class);
		when(handlerMethod.getMethod()).then(i -> ControllerAudit.class.getMethod("verbCantDoErrors"));

		controlerInterceptor.afterCompletion(request, response, handlerMethod, exception);
		verify(auditService, never()).interceptForbiddenRequest(request);
		verify(auditService, never()).interceptUnauthorizedRequest(request);
		verify(auditService, never()).onChangeSecurity(request, null);
		verify(auditService, atLeastOnce())
		        .onImportantError(request, List.of("cantDoErrors"), exception);
		verify(auditService, atLeastOnce()).onSimpleEvent(request, List.of("OnClass"));
		verify(auditService, never()).onUseSecurity(request, null);
		verify(auditService, never()).onRejectLogin(request, null, null, null);
		verify(auditService, never()).onLogin(request, null, null);
	}

	@Test
	public void afterCompletionAudit_verbAll() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerAudit.class);
		when(handlerMethod.getMethod()).then(i -> ControllerAudit.class.getMethod("verbAll"));

		controlerInterceptor.afterCompletion(request, response, handlerMethod, exception);
		verify(auditService, never()).interceptForbiddenRequest(request);
		verify(auditService, never()).interceptUnauthorizedRequest(request);
		verify(auditService, atLeastOnce()).onChangeSecurity(request, List.of("All"));
		verify(auditService, atLeastOnce())
		        .onImportantError(request, List.of("All"), exception);
		verify(auditService, atLeastOnce()).onSimpleEvent(request, List.of("OnClass"));
		verify(auditService, atLeastOnce()).onUseSecurity(request, List.of("All"));
		verify(auditService, never()).onRejectLogin(request, null, null, null);
		verify(auditService, never()).onLogin(request, null, null);
	}

	@Test
	public void afterCompletionAudit_verbSimple() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerAudit.class);
		when(handlerMethod.getMethod()).then(i -> ControllerAudit.class.getMethod("verbSimple"));

		controlerInterceptor.afterCompletion(request, response, handlerMethod, exception);
		verify(auditService, never()).interceptForbiddenRequest(request);
		verify(auditService, never()).interceptUnauthorizedRequest(request);
		verify(auditService, never()).onChangeSecurity(request, null);
		verify(auditService, never()).onImportantError(request, null, null);
		verify(auditService, atLeastOnce()).onSimpleEvent(request, List.of("OnClass", "simple"));
		verify(auditService, never()).onUseSecurity(request, null);
		verify(auditService, never()).onRejectLogin(request, null, null, null);
		verify(auditService, never()).onLogin(request, null, null);
	}

	@Test
	public void afterCompletionAudit_verbCombinated() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerAudit.class);
		when(handlerMethod.getMethod()).then(i -> ControllerAudit.class.getMethod("verbCombinated"));

		controlerInterceptor.afterCompletion(request, response, handlerMethod, exception);
		verify(auditService, never()).interceptForbiddenRequest(request);
		verify(auditService, never()).interceptUnauthorizedRequest(request);
		verify(auditService, never()).onChangeSecurity(request, null);
		verify(auditService, never()).onImportantError(request, null, null);
		verify(auditService, atLeastOnce())
		        .onSimpleEvent(request, List.of("OnClass", "combinated1", "combinated2"));
		verify(auditService, never()).onUseSecurity(request, null);
		verify(auditService, never()).onRejectLogin(request, null, null, null);
		verify(auditService, never()).onLogin(request, null, null);
	}

	@Test
	public void preHandleUserLoggedWithoutRights_CtrlWithoutSecure_verbWithSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithoutSecure.class);
		when(handlerMethod.getMethod()).then(i -> ControllerWithoutSecure.class.getMethod("verbWithSecure"));
		when(request.getMethod()).thenReturn("GET");

		final var token = makeRandomString().replace(' ', '_');
		when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
		final var loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of(), new Date());
		when(securedTokenService.loggedUserRightsExtractToken(eq(token))).thenReturn(loggedUserTagsDto);

		assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(response, atLeastOnce()).reset();
		verify(response, atLeastOnce()).sendError(FORBIDDEN.value());

		verify(auditService, atLeastOnce()).interceptForbiddenRequest(request);
		verify(auditService, never()).interceptUnauthorizedRequest(request);
		verify(auditService, never()).onChangeSecurity(request, null);
		verify(auditService, never()).onImportantError(request, null, null);
		verify(auditService, never()).onSimpleEvent(request, null);
		verify(auditService, never()).onUseSecurity(request, null);
		verify(auditService, never()).onRejectLogin(request, null, null, null);
		verify(auditService, never()).onLogin(request, null, null);
	}

	@Test
	public void preHandleUserLoggedWithoutRights_CtrlWithSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithSecure.class);
		when(handlerMethod.getMethod()).then(i -> ControllerWithSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		final var token = makeRandomString().replace(' ', '_');
		when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
		final var loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of(), new Date());
		when(securedTokenService.loggedUserRightsExtractToken(eq(token))).thenReturn(loggedUserTagsDto);

		/**
		 * Have some trouble with unit tests (flaky).
		 */
		assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(response, atLeastOnce()).reset();
		verify(response, atLeastOnce()).sendError(FORBIDDEN.value());

		verify(auditService, atLeastOnce()).interceptForbiddenRequest(request);
		verify(auditService, never()).interceptUnauthorizedRequest(request);
		verify(auditService, never()).onChangeSecurity(request, null);
		verify(auditService, never()).onImportantError(request, null, null);
		verify(auditService, never()).onSimpleEvent(request, null);
		verify(auditService, never()).onUseSecurity(request, null);
		verify(auditService, never()).onRejectLogin(request, null, null, null);
		verify(auditService, never()).onLogin(request, null, null);
	}

	@Test
	public void preHandleUserLoggedWithRights_CtrlWithoutSecure_verbWithSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithoutSecure.class);
		when(handlerMethod.getMethod()).then(i -> ControllerWithoutSecure.class.getMethod("verbWithSecure"));
		when(request.getMethod()).thenReturn("GET");

		final var token = makeRandomString().replace(' ', '_');
		when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
		final var loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secureOnMethod"), new Date());
		when(securedTokenService.loggedUserRightsExtractToken(eq(token))).thenReturn(loggedUserTagsDto);

		assertTrue(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(response, never()).reset();
		verify(response, never()).sendError(anyInt());

		verify(auditService, never()).interceptForbiddenRequest(request);
		verify(auditService, never()).interceptUnauthorizedRequest(request);
		verify(auditService, never()).onChangeSecurity(request, null);
		verify(auditService, never()).onImportantError(request, null, null);
		verify(auditService, never()).onSimpleEvent(request, null);
		verify(auditService, never()).onUseSecurity(request, null);
		verify(auditService, never()).onRejectLogin(request, null, null, null);
		verify(auditService, never()).onLogin(request, null, null);
	}

	@Test
	public void preHandleUserLoggedWithRights_CtrlWithSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithSecure.class);
		when(handlerMethod.getMethod()).then(i -> ControllerWithSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		final var token = makeRandomString().replace(' ', '_');
		when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
		final var loggedUserTagsDto = new LoggedUserTagsTokenDto(
		        uuid, Set.of("secureOnClass", "secureOnMethod"), new Date());
		when(securedTokenService.loggedUserRightsExtractToken(eq(token))).thenReturn(loggedUserTagsDto);

		assertTrue(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(response, never()).reset();
		verify(response, never()).sendError(anyInt());

		verify(auditService, never()).interceptForbiddenRequest(request);
		verify(auditService, never()).interceptUnauthorizedRequest(request);
		verify(auditService, never()).onChangeSecurity(request, null);
		verify(auditService, never()).onImportantError(request, null, null);
		verify(auditService, never()).onSimpleEvent(request, null);
		verify(auditService, never()).onUseSecurity(request, null);
		verify(auditService, never()).onRejectLogin(request, null, null, null);
		verify(auditService, never()).onLogin(request, null, null);
	}

	@Test
	public void preHandleUserLoggedWithRights_InvalidRightsLinkedIP() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithSecure.class);
		when(handlerMethod.getMethod()).then(i -> ControllerWithSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		final var token = makeRandomString().replace(' ', '_');
		when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
		final var loggedUserTagsDto = new LoggedUserTagsTokenDto(
		        uuid, Set.of("secureOnClass", "secureOnMethod"), new Date(), makeRandomIPv4().getHostAddress());
		when(securedTokenService.loggedUserRightsExtractToken(eq(token))).thenReturn(loggedUserTagsDto);

		assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(response, atLeastOnce()).reset();
		verify(response, atLeastOnce()).sendError(UNAUTHORIZED.value());

		verify(auditService, never()).interceptForbiddenRequest(request);
		verify(auditService, atLeastOnce()).interceptUnauthorizedRequest(request);
		verify(auditService, never()).onChangeSecurity(request, null);
		verify(auditService, never()).onImportantError(request, null, null);
		verify(auditService, never()).onSimpleEvent(request, null);
		verify(auditService, never()).onUseSecurity(request, null);
		verify(auditService, never()).onRejectLogin(request, null, null, null);
		verify(auditService, never()).onLogin(request, null, null);
	}

	@Test
	public void preHandleUserLoggedWithRights_ValidRightsLinkedIP() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithSecure.class);
		when(handlerMethod.getMethod()).then(i -> ControllerWithSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		final var token = makeRandomString().replace(' ', '_');
		when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
		final var loggedUserTagsDto = new LoggedUserTagsTokenDto(
		        uuid, Set.of("secureOnClass", "secureOnMethod"), new Date(), request.getRemoteAddr());
		when(securedTokenService.loggedUserRightsExtractToken(eq(token))).thenReturn(loggedUserTagsDto);

		assertTrue(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(response, never()).reset();
		verify(response, never()).sendError(anyInt());

		verify(auditService, never()).interceptForbiddenRequest(request);
		verify(auditService, never()).interceptUnauthorizedRequest(request);
		verify(auditService, never()).onChangeSecurity(request, null);
		verify(auditService, never()).onImportantError(request, null, null);
		verify(auditService, never()).onSimpleEvent(request, null);
		verify(auditService, never()).onUseSecurity(request, null);
		verify(auditService, never()).onRejectLogin(request, null, null, null);
		verify(auditService, never()).onLogin(request, null, null);
	}

	@Nested
	class DoNotSecureChecks {

		@Mock
		private ResourceHttpRequestHandler resourceHttpRequest;

		@BeforeEach
		public void initMocks() {
			MockitoAnnotations.initMocks(this);
		}

		private void afterEach() {
			verify(auditService, never()).interceptForbiddenRequest(request);
			verify(auditService, never()).interceptUnauthorizedRequest(request);
			verify(auditService, never()).onChangeSecurity(request, null);
			verify(auditService, never()).onImportantError(request, null, null);
			verify(auditService, never()).onSimpleEvent(request, null);
			verify(auditService, never()).onUseSecurity(request, null);
			verify(auditService, never()).onRejectLogin(request, null, null, null);
			verify(auditService, never()).onLogin(request, null, null);
		}

		@Test
		public void preHandleHttpRequest() throws Exception {
			assertTrue(controlerInterceptor.preHandle(request, response, resourceHttpRequest));
			afterEach();
		}

		@Test
		public void afterCompletionHttpRequest() throws Exception {
			controlerInterceptor.afterCompletion(request, response, resourceHttpRequest, null);
			afterEach();
		}

		@Test
		public void preHandleOtherRequest() throws Exception {
			assertTrue(controlerInterceptor.preHandle(request, response, new Object()));
			afterEach();
		}

		@Test
		public void afterCompletionOtherRequest() throws Exception {
			controlerInterceptor.afterCompletion(request, response, new Object(), null);
			afterEach();
		}
	}

	@Nested
	class PreHandleUserLoggedWithRights_RenforceCheck {

		@Test
		public void method_badRights() throws Exception {
			when(handlerMethod.getBeanType()).then(i -> ControllerMethodRequireRenforceCheck.class);
			when(handlerMethod.getMethod()).then(i -> ControllerMethodRequireRenforceCheck.class.getMethod("verb"));
			when(request.getMethod()).thenReturn("GET");

			final var token = makeRandomString().replace(' ', '_');
			when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
			final var loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secured"), new Date());
			when(securedTokenService.loggedUserRightsExtractToken(eq(token))).thenReturn(loggedUserTagsDto);

			when(authenticationService.getRightsForUser(eq(uuid), eq("127.0.0.1"))).thenReturn(List.of("another"));
			when(authenticationService.isUserEnabledAndNonBlocked(eq(uuid))).thenReturn(true);

			assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

			verify(response, atLeastOnce()).reset();
			verify(response, atLeastOnce()).sendError(FORBIDDEN.value());

			verify(auditService, atLeastOnce()).interceptForbiddenRequest(request);
			verify(auditService, never()).interceptUnauthorizedRequest(request);
			verify(auditService, never()).onChangeSecurity(request, null);
			verify(auditService, never()).onImportantError(request, null, null);
			verify(auditService, never()).onSimpleEvent(request, null);
			verify(auditService, never()).onUseSecurity(request, null);
			verify(auditService, never()).onRejectLogin(request, null, null, null);
			verify(auditService, never()).onLogin(request, null, null);
		}

		@Test
		public void method_badDisabledOrBlocked() throws Exception {
			when(handlerMethod.getBeanType()).then(i -> ControllerMethodRequireRenforceCheck.class);
			when(handlerMethod.getMethod()).then(i -> ControllerMethodRequireRenforceCheck.class.getMethod("verb"));
			when(request.getMethod()).thenReturn("GET");

			final var token = makeRandomString().replace(' ', '_');
			when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
			final var loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secured"), new Date());
			when(securedTokenService.loggedUserRightsExtractToken(eq(token))).thenReturn(loggedUserTagsDto);

			when(authenticationService.getRightsForUser(eq(uuid), eq("127.0.0.1"))).thenReturn(List.of("secured"));
			when(authenticationService.isUserEnabledAndNonBlocked(eq(uuid))).thenReturn(false);

			assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

			verify(response, atLeastOnce()).reset();
			verify(response, atLeastOnce()).sendError(UNAUTHORIZED.value());

			verify(auditService, never()).interceptForbiddenRequest(request);
			verify(auditService, atLeastOnce()).interceptUnauthorizedRequest(request);
			verify(auditService, never()).onChangeSecurity(request, null);
			verify(auditService, never()).onImportantError(request, null, null);
			verify(auditService, never()).onSimpleEvent(request, null);
			verify(auditService, never()).onUseSecurity(request, null);
			verify(auditService, never()).onRejectLogin(request, null, null, null);
			verify(auditService, never()).onLogin(request, null, null);
		}

		@Test
		public void class_badRights() throws Exception {
			when(handlerMethod.getBeanType()).then(i -> ControllerClassRequireRenforceCheck.class);
			when(handlerMethod.getMethod()).then(i -> ControllerClassRequireRenforceCheck.class.getMethod("verb"));
			when(request.getMethod()).thenReturn("GET");

			final var token = makeRandomString().replace(' ', '_');
			when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
			final var loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secured"), new Date());
			when(securedTokenService.loggedUserRightsExtractToken(eq(token))).thenReturn(loggedUserTagsDto);

			when(authenticationService.getRightsForUser(eq(uuid), eq("127.0.0.1"))).thenReturn(List.of("another"));
			when(authenticationService.isUserEnabledAndNonBlocked(eq(uuid))).thenReturn(true);

			assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

			verify(response, atLeastOnce()).reset();
			verify(response, atLeastOnce()).sendError(FORBIDDEN.value());

			verify(auditService, atLeastOnce()).interceptForbiddenRequest(request);
			verify(auditService, never()).interceptUnauthorizedRequest(request);
			verify(auditService, never()).onChangeSecurity(request, null);
			verify(auditService, never()).onImportantError(request, null, null);
			verify(auditService, never()).onSimpleEvent(request, null);
			verify(auditService, never()).onUseSecurity(request, null);
			verify(auditService, never()).onRejectLogin(request, null, null, null);
			verify(auditService, never()).onLogin(request, null, null);
		}

		@Test
		public void class_badDisabledOrBlocked() throws Exception {
			when(handlerMethod.getBeanType()).then(i -> ControllerClassRequireRenforceCheck.class);
			when(handlerMethod.getMethod()).then(i -> ControllerClassRequireRenforceCheck.class.getMethod("verb"));
			when(request.getMethod()).thenReturn("GET");

			final var token = makeRandomString().replace(' ', '_');
			when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
			final var loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secured"), new Date());
			when(securedTokenService.loggedUserRightsExtractToken(eq(token))).thenReturn(loggedUserTagsDto);

			when(authenticationService.getRightsForUser(eq(uuid), eq("127.0.0.1"))).thenReturn(List.of("secured"));
			when(authenticationService.isUserEnabledAndNonBlocked(eq(uuid))).thenReturn(false);

			assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

			verify(response, atLeastOnce()).reset();
			verify(response, atLeastOnce()).sendError(UNAUTHORIZED.value());

			verify(auditService, never()).interceptForbiddenRequest(request);
			verify(auditService, atLeastOnce()).interceptUnauthorizedRequest(request);
			verify(auditService, never()).onChangeSecurity(request, null);
			verify(auditService, never()).onImportantError(request, null, null);
			verify(auditService, never()).onSimpleEvent(request, null);
			verify(auditService, never()).onUseSecurity(request, null);
			verify(auditService, never()).onRejectLogin(request, null, null, null);
			verify(auditService, never()).onLogin(request, null, null);
		}

	}

}
