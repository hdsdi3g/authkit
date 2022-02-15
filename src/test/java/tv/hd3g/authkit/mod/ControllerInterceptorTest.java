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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static tv.hd3g.authkit.mod.ControllerInterceptor.CONTROLLER_TYPE_ATTRIBUTE_NAME;
import static tv.hd3g.authkit.mod.ControllerInterceptor.USER_TOKEN_ATTRIBUTE_NAME;
import static tv.hd3g.authkit.mod.ControllerInterceptor.USER_UUID_ATTRIBUTE_NAME;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomIPv4;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomString;
import static tv.hd3g.authkit.tool.DataGenerator.makeUUID;
import static tv.hd3g.authkit.utility.ControllerType.CLASSIC;
import static tv.hd3g.authkit.utility.ControllerType.REST;

import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.resource.ResourceHttpRequestHandler;

import tv.hd3g.authkit.dummy.controller.CheckClosedCtrl;
import tv.hd3g.authkit.dummy.controller.CheckWORightsCtrl;
import tv.hd3g.authkit.dummy.controller.CheckWORightsRestCtrl;
import tv.hd3g.authkit.dummy.controller.ControllerAudit;
import tv.hd3g.authkit.dummy.controller.ControllerClassRequireRenforceCheck;
import tv.hd3g.authkit.dummy.controller.ControllerMethodRequireRenforceCheck;
import tv.hd3g.authkit.dummy.controller.ControllerWithSecure;
import tv.hd3g.authkit.dummy.controller.ControllerWithoutSecure;
import tv.hd3g.authkit.dummy.controller.RESTControllerWithoutSecure;
import tv.hd3g.authkit.mod.component.AuthKitEndpointsListener;
import tv.hd3g.authkit.mod.dto.LoggedUserTagsTokenDto;
import tv.hd3g.authkit.mod.exception.BadRequestException;
import tv.hd3g.authkit.mod.exception.ForbiddenRequestException;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException.BadUseSecuredTokenInvalidType;
import tv.hd3g.authkit.mod.exception.UnauthorizedRequestException;
import tv.hd3g.authkit.mod.repository.UserRepository;
import tv.hd3g.authkit.mod.service.AuditReportService;
import tv.hd3g.authkit.mod.service.AuthenticationService;
import tv.hd3g.authkit.mod.service.CookieService;
import tv.hd3g.authkit.mod.service.SecuredTokenService;
import tv.hd3g.authkit.tool.DataGenerator;

class ControllerInterceptorTest {

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
	@Mock
	private CookieService cookieService;

	private AuthKitEndpointsListener authKitEndpointsListener;
	private ControllerInterceptor controlerInterceptor;
	private String uuid;
	private String clientAddr;
	private String token;
	private LoggedUserTagsTokenDto loggedUserTagsDto;

	@BeforeEach
	void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		DataGenerator.setupMock(request);
		clientAddr = "127.0.0.1";
		authKitEndpointsListener = new AuthKitEndpointsListener();
		controlerInterceptor = new ControllerInterceptor(
		        auditService, securedTokenService, authKitEndpointsListener, authenticationService, cookieService);
		uuid = makeUUID();
		token = makeRandomString().replace(' ', '_');
		loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of(), new Date(), false);
	}

	@AfterEach
	void end() {
		Mockito.verifyNoMoreInteractions(auditService,
		        securedTokenService,
		        request,
		        response,
		        handlerMethod,
		        exception,
		        userRepository,
		        authenticationService,
		        cookieService);
	}

	@Test
	void preHandleUserNotLogged_CtrlWithoutSecure_verbWithoutSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithoutSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithoutSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		assertTrue(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(request, atLeastOnce()).setAttribute(eq(USER_UUID_ATTRIBUTE_NAME), isNull());
		verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
		verify(request, atLeastOnce()).getMethod();
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
		verify(cookieService, atLeastOnce()).getLogonCookiePayload(request);
		verify(cookieService, atLeastOnce()).getRedirectAfterLoginCookiePayload(request);
		verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, CLASSIC);
	}

	@Test
	void preHandleUserNotLogged_CtrlWithoutSecure_verbWithSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithoutSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithoutSecure.class.getMethod("verbWithSecure"));
		when(request.getMethod()).thenReturn("GET");

		assertThrows(UnauthorizedRequestException.class,
		        () -> controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
		verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, CLASSIC);

		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
		verify(cookieService, atLeastOnce()).getLogonCookiePayload(request);
	}

	@Test
	void preHandleUserNotLogged_CtrlWithSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		assertThrows(UnauthorizedRequestException.class,
		        () -> controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
		verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, CLASSIC);
		// verify(request, atLeastOnce()).getMethod();
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
		verify(cookieService, atLeastOnce()).getLogonCookiePayload(request);
	}

	@Test
	void afterCompletionAudit_NoAudit() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithoutSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithoutSecure.class.getMethod("verbWithoutSecure"));

		controlerInterceptor.afterCompletion(request, response, handlerMethod, exception);

		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
	}

	@Test
	void afterCompletionAudit_verbUseSecurity() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerAudit.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerAudit.class.getMethod("verbUseSecurity"));

		controlerInterceptor.afterCompletion(request, response, handlerMethod, exception);
		verify(auditService, atLeastOnce()).onSimpleEvent(request, List.of("OnClass"));
		verify(auditService, atLeastOnce()).onUseSecurity(request, List.of("useSecurity"));

		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
	}

	@Test
	void afterCompletionAudit_verbChangeSecurity() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerAudit.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerAudit.class.getMethod("verbChangeSecurity"));

		controlerInterceptor.afterCompletion(request, response, handlerMethod, exception);
		verify(auditService, atLeastOnce()).onChangeSecurity(request, List.of("changeSecurity"));
		verify(auditService, atLeastOnce()).onSimpleEvent(request, List.of("OnClass"));

		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
	}

	@Test
	void afterCompletionAudit_verbCantDoErrors() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerAudit.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerAudit.class.getMethod("verbCantDoErrors"));

		controlerInterceptor.afterCompletion(request, response, handlerMethod, exception);
		verify(auditService, atLeastOnce())
		        .onImportantError(request, List.of("cantDoErrors"), exception);
		verify(auditService, atLeastOnce()).onSimpleEvent(request, List.of("OnClass"));

		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
	}

	@Test
	void afterCompletionAudit_verbAll() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerAudit.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerAudit.class.getMethod("verbAll"));

		controlerInterceptor.afterCompletion(request, response, handlerMethod, exception);
		verify(auditService, atLeastOnce()).onChangeSecurity(request, List.of("All"));
		verify(auditService, atLeastOnce())
		        .onImportantError(request, List.of("All"), exception);
		verify(auditService, atLeastOnce()).onSimpleEvent(request, List.of("OnClass"));
		verify(auditService, atLeastOnce()).onUseSecurity(request, List.of("All"));

		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
	}

	@Test
	void afterCompletionAudit_verbSimple() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerAudit.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerAudit.class.getMethod("verbSimple"));

		controlerInterceptor.afterCompletion(request, response, handlerMethod, exception);
		verify(auditService, atLeastOnce()).onSimpleEvent(request, List.of("OnClass", "simple"));

		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
	}

	@Test
	void afterCompletionAudit_verbCombinated() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerAudit.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerAudit.class.getMethod("verbCombinated"));

		controlerInterceptor.afterCompletion(request, response, handlerMethod, exception);
		verify(auditService, atLeastOnce())
		        .onSimpleEvent(request, List.of("OnClass", "combinated1", "combinated2"));

		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
		verify(auditService, never()).onLogin(request, null, null);
	}

	@Test
	void preHandleUserLoggedWithoutRights_CtrlWithoutSecure_verbWithSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithoutSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithoutSecure.class.getMethod("verbWithSecure"));
		when(request.getMethod()).thenReturn("GET");

		when(request.getHeader(AUTHORIZATION)).thenReturn("bearer " + token);
		when(securedTokenService.loggedUserRightsExtractToken(token, false)).thenReturn(loggedUserTagsDto);

		assertThrows(ForbiddenRequestException.class,
		        () -> controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
		verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
		verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, CLASSIC);
		verify(request, atLeastOnce()).setAttribute(USER_TOKEN_ATTRIBUTE_NAME, loggedUserTagsDto);

		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
	}

	@Test
	void preHandleUserLoggedWithoutRights_CtrlWithSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		when(request.getHeader(AUTHORIZATION)).thenReturn("bearer " + token);

		when(securedTokenService.loggedUserRightsExtractToken(token, false)).thenReturn(loggedUserTagsDto);

		/**
		 * Have some trouble with unit tests (flaky).
		 */
		assertThrows(ForbiddenRequestException.class,
		        () -> controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
		verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
		verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, CLASSIC);
		verify(request, atLeastOnce()).setAttribute(USER_TOKEN_ATTRIBUTE_NAME, loggedUserTagsDto);

		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
	}

	@Test
	void preHandleUserLoggedWithRights_CtrlWithoutSecure_verbWithSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithoutSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithoutSecure.class.getMethod("verbWithSecure"));
		when(request.getMethod()).thenReturn("GET");

		when(request.getHeader(AUTHORIZATION)).thenReturn("bearer " + token);
		loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secureOnMethod"), new Date(), false);
		when(securedTokenService.loggedUserRightsExtractToken(token, false)).thenReturn(loggedUserTagsDto);

		assertTrue(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
		verify(request, atLeastOnce()).setAttribute(USER_UUID_ATTRIBUTE_NAME, uuid);
		verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, CLASSIC);
		verify(request, atLeastOnce()).setAttribute(USER_TOKEN_ATTRIBUTE_NAME, loggedUserTagsDto);
		verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
		verify(request, atLeastOnce()).getMethod();
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
		verify(cookieService, atLeastOnce()).getRedirectAfterLoginCookiePayload(request);
	}

	@Test
	void preHandleUserLoggedWithRightsViaCookieOnly_RESTCtrlSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> RESTControllerWithoutSecure.class);
		when(handlerMethod.getMethod()).thenReturn(RESTControllerWithoutSecure.class.getMethod("verbWithSecure"));
		when(request.getMethod()).thenReturn("GET");

		when(cookieService.getLogonCookiePayload(request)).thenReturn(token);
		when(request.getHeader(AUTHORIZATION)).thenReturn(null);
		loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secureOnMethod"), new Date(), true);
		when(securedTokenService.loggedUserRightsExtractToken(token, true)).thenReturn(loggedUserTagsDto);

		final var deleteCookie = Mockito.mock(Cookie.class);
		when(cookieService.deleteLogonCookie()).thenReturn(deleteCookie);

		assertThrows(UnauthorizedRequestException.class,
		        () -> controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
		verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
		verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, REST);
		verify(request, atLeastOnce()).setAttribute(USER_TOKEN_ATTRIBUTE_NAME, loggedUserTagsDto);

		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
		verify(cookieService, atLeastOnce()).getLogonCookiePayload(request);

	}

	@Test
	void preHandleUserLogged_EmptyRights_ViaCookieOnly() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> CheckWORightsCtrl.class);
		when(handlerMethod.getMethod()).thenReturn(CheckWORightsCtrl.class.getMethod("verb"));
		when(request.getMethod()).thenReturn("GET");

		when(cookieService.getLogonCookiePayload(request)).thenReturn(token);
		when(request.getHeader(AUTHORIZATION)).thenReturn(null);
		loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of(), new Date(), true);
		when(securedTokenService.loggedUserRightsExtractToken(token, true)).thenReturn(loggedUserTagsDto);

		assertTrue(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
		verify(request, atLeastOnce()).setAttribute(USER_UUID_ATTRIBUTE_NAME, uuid);
		verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, CLASSIC);
		verify(request, atLeastOnce()).setAttribute(USER_TOKEN_ATTRIBUTE_NAME, loggedUserTagsDto);
		verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
		verify(request, atLeastOnce()).getMethod();
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
		verify(cookieService, atLeastOnce()).getLogonCookiePayload(request);
		verify(cookieService, atLeastOnce()).getRedirectAfterLoginCookiePayload(request);
	}

	@Test
	void preHandleUserLogged_EmptyRights_ViaBearerOnly() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> CheckWORightsRestCtrl.class);
		when(handlerMethod.getMethod()).thenReturn(CheckWORightsRestCtrl.class.getMethod("verb"));
		when(request.getMethod()).thenReturn("GET");

		when(request.getHeader(AUTHORIZATION)).thenReturn("bearer " + token);

		when(securedTokenService.loggedUserRightsExtractToken(token, false)).thenReturn(loggedUserTagsDto);

		assertTrue(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
		verify(request, atLeastOnce()).setAttribute(USER_UUID_ATTRIBUTE_NAME, uuid);
		verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, REST);
		verify(request, atLeastOnce()).setAttribute(USER_TOKEN_ATTRIBUTE_NAME, loggedUserTagsDto);
		verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
		verify(request, atLeastOnce()).getMethod();
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
		verify(cookieService, atLeastOnce()).getRedirectAfterLoginCookiePayload(request);
	}

	@Test
	void preHandleUserNotLogged_EmptyRights() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> CheckWORightsRestCtrl.class);
		when(handlerMethod.getMethod()).thenReturn(CheckWORightsRestCtrl.class.getMethod("verb"));
		when(request.getMethod()).thenReturn("GET");

		when(request.getHeader(AUTHORIZATION)).thenReturn(null);

		assertThrows(UnauthorizedRequestException.class,
		        () -> controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
		verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, REST);

		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
		verify(cookieService, atLeastOnce()).getLogonCookiePayload(request);
	}

	@Nested
	class PreHandleUserLoggedWithRights_ViaCookieOnly {
		String token;

		@BeforeEach
		void init() throws Exception {
			when(handlerMethod.getBeanType()).then(i -> CheckClosedCtrl.class);

			token = makeRandomString().replace(' ', '_');
			when(cookieService.getLogonCookiePayload(request)).thenReturn(token);
			when(request.getHeader(AUTHORIZATION)).thenReturn(null);
			loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secureOnClass"), new Date(), true);
			when(securedTokenService.loggedUserRightsExtractToken(token, true)).thenReturn(loggedUserTagsDto);
		}

		@ParameterizedTest
		@CsvSource({
		             "verbGET, GET",
		             "verbPOST, POST",
		})
		void ok(final String method, final String verb) throws Exception {
			when(handlerMethod.getMethod()).thenReturn(CheckClosedCtrl.class.getMethod(method));
			when(request.getMethod()).thenReturn(verb);

			assertTrue(controlerInterceptor.preHandle(request, response, handlerMethod));

			verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
			verify(request, atLeastOnce()).setAttribute(USER_UUID_ATTRIBUTE_NAME, uuid);
			verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, CLASSIC);
			verify(request, atLeastOnce()).setAttribute(USER_TOKEN_ATTRIBUTE_NAME, loggedUserTagsDto);
			verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
			verify(request, atLeastOnce()).getMethod();
			verify(handlerMethod, atLeastOnce()).getBeanType();
			verify(handlerMethod, atLeastOnce()).getMethod();
			verify(cookieService, atLeastOnce()).getLogonCookiePayload(request);
			verify(cookieService, atLeastOnce()).getRedirectAfterLoginCookiePayload(request);
		}

		@ParameterizedTest
		@CsvSource({
		             "verbPUT, PUT",
		             "verbDELETE, DELETE",
		             "verbPATCH, PATCH",
		})
		void fail(final String method, final String verb) throws Exception {
			final var deleteCookie = Mockito.mock(Cookie.class);
			when(cookieService.deleteLogonCookie()).thenReturn(deleteCookie);

			when(handlerMethod.getMethod()).thenReturn(CheckClosedCtrl.class.getMethod(method));
			when(request.getMethod()).thenReturn(verb);

			assertThrows(BadRequestException.class,
			        () -> controlerInterceptor.preHandle(request, response, handlerMethod));

			verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
			verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
			verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, CLASSIC);
			verify(request, atLeastOnce()).setAttribute(USER_TOKEN_ATTRIBUTE_NAME, loggedUserTagsDto);
			verify(request, atLeastOnce()).getMethod();

			verify(handlerMethod, atLeastOnce()).getBeanType();
			verify(handlerMethod, atLeastOnce()).getMethod();
			verify(cookieService, atLeastOnce()).getLogonCookiePayload(request);

			Mockito.verifyNoMoreInteractions(deleteCookie);
		}
	}

	@Test
	void preHandleUserLoggedWithRights_CtrlWithSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		when(request.getHeader(AUTHORIZATION)).thenReturn("bearer " + token);
		loggedUserTagsDto = new LoggedUserTagsTokenDto(
		        uuid, Set.of("secureOnClass", "secureOnMethod"), new Date(), false);
		when(securedTokenService.loggedUserRightsExtractToken(token, false)).thenReturn(loggedUserTagsDto);

		assertTrue(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
		verify(request, atLeastOnce()).setAttribute(USER_UUID_ATTRIBUTE_NAME, uuid);
		verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, CLASSIC);
		verify(request, atLeastOnce()).setAttribute(USER_TOKEN_ATTRIBUTE_NAME, loggedUserTagsDto);
		verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
		verify(request, atLeastOnce()).getMethod();
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
		verify(cookieService, atLeastOnce()).getRedirectAfterLoginCookiePayload(request);
	}

	@Test
	void preHandleUserLoggedWithRights_InvalidRightsLinkedIP() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		when(request.getHeader(AUTHORIZATION)).thenReturn("bearer " + token);
		loggedUserTagsDto = new LoggedUserTagsTokenDto(
		        uuid, Set.of("secureOnClass", "secureOnMethod"), new Date(), false, makeRandomIPv4()
		                .getHostAddress());
		when(securedTokenService.loggedUserRightsExtractToken(token, false)).thenReturn(loggedUserTagsDto);

		assertThrows(UnauthorizedRequestException.class,
		        () -> controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
		verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
		verify(request, atLeastOnce()).getHeader("X-Forwarded-For");
		verify(request, atLeastOnce()).getRemoteAddr();
		verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, CLASSIC);
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
	}

	@Test
	void preHandleInvalidBearer_ButCookieLogged() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		final var token0 = makeRandomString().replace(' ', '_');
		when(request.getHeader(AUTHORIZATION)).thenReturn("bearer " + token0);
		when(securedTokenService.loggedUserRightsExtractToken(token0, false))
		        .thenThrow(BadUseSecuredTokenInvalidType.class);

		final var token1 = makeRandomString().replace(' ', '_');
		when(cookieService.getLogonCookiePayload(request)).thenReturn(token1);
		final var loggedUserTagsDto1 = new LoggedUserTagsTokenDto(
		        uuid, Set.of("secureOnClass", "secureOnMethod"), new Date(), true);
		when(securedTokenService.loggedUserRightsExtractToken(token1, true)).thenReturn(loggedUserTagsDto1);

		final var deleteCookie = Mockito.mock(Cookie.class);
		when(cookieService.deleteLogonCookie()).thenReturn(deleteCookie);

		assertThrows(UnauthorizedRequestException.class,
		        () -> controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token0), anyBoolean());
		verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
		verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, CLASSIC);
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
	}

	@Test
	void preHandleUserLoggedWithRights_ValidRightsLinkedIP() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		token = makeRandomString().replace(' ', '_');
		when(request.getHeader(AUTHORIZATION)).thenReturn("bearer " + token);
		loggedUserTagsDto = new LoggedUserTagsTokenDto(
		        uuid, Set.of("secureOnClass", "secureOnMethod"), new Date(), false, clientAddr);
		when(securedTokenService.loggedUserRightsExtractToken(token, false)).thenReturn(loggedUserTagsDto);

		assertTrue(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
		verify(request, atLeastOnce()).setAttribute(USER_UUID_ATTRIBUTE_NAME, uuid);
		verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, CLASSIC);
		verify(request, atLeastOnce()).setAttribute(USER_TOKEN_ATTRIBUTE_NAME, loggedUserTagsDto);
		verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
		verify(request, atLeastOnce()).getHeader("X-Forwarded-For");
		verify(request, atLeastOnce()).getMethod();
		verify(request, atLeastOnce()).getRemoteAddr();

		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();

		verify(cookieService, atLeastOnce()).getRedirectAfterLoginCookiePayload(request);
	}

	@Nested
	class DoNotSecureChecks {

		@Mock
		private ResourceHttpRequestHandler resourceHttpRequest;

		@BeforeEach
		void initMocks() throws Exception {
			MockitoAnnotations.openMocks(this).close();
		}

		@AfterEach
		void end() {
			Mockito.verifyNoMoreInteractions(auditService);
		}

		@Test
		void preHandleHttpRequest() throws Exception {
			assertTrue(controlerInterceptor.preHandle(request, response, resourceHttpRequest));
		}

		@Test
		void afterCompletionHttpRequest() throws Exception {
			assertDoesNotThrow(() -> controlerInterceptor
			        .afterCompletion(request, response, resourceHttpRequest, null));
		}

		@Test
		void preHandleOtherRequest() throws Exception {
			assertTrue(controlerInterceptor.preHandle(request, response, new Object()));
		}

		@Test
		void afterCompletionOtherRequest() throws Exception {
			assertDoesNotThrow(() -> controlerInterceptor
			        .afterCompletion(request, response, new Object(), null));
		}
	}

	@Nested
	class PreHandleUserLoggedWithRights_RenforceCheck {

		@Test
		void method_badRights() throws Exception {
			when(handlerMethod.getBeanType()).then(i -> ControllerMethodRequireRenforceCheck.class);
			when(handlerMethod.getMethod()).thenReturn(ControllerMethodRequireRenforceCheck.class.getMethod(
			        "verb"));
			when(request.getMethod()).thenReturn("GET");

			when(request.getHeader(AUTHORIZATION)).thenReturn("bearer " + token);
			loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secured"), new Date(), false);
			when(securedTokenService.loggedUserRightsExtractToken(token, false)).thenReturn(
			        loggedUserTagsDto);

			when(authenticationService.getRightsForUser(uuid, clientAddr)).thenReturn(List.of("another"));
			when(authenticationService.isUserEnabledAndNonBlocked(uuid)).thenReturn(true);

			assertThrows(ForbiddenRequestException.class,
			        () -> controlerInterceptor.preHandle(request, response, handlerMethod));

			verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
			verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
			verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, CLASSIC);
			verify(request, atLeastOnce()).setAttribute(USER_TOKEN_ATTRIBUTE_NAME, loggedUserTagsDto);
			verify(request, atLeastOnce()).getHeader("X-Forwarded-For");
			verify(request, atLeastOnce()).getRemoteAddr();
			verify(handlerMethod, atLeastOnce()).getBeanType();
			verify(handlerMethod, atLeastOnce()).getMethod();
			verify(authenticationService, atLeastOnce()).isUserEnabledAndNonBlocked(uuid);
			verify(authenticationService, atLeastOnce()).getRightsForUser(uuid, clientAddr);
		}

		@Test
		void method_badDisabledOrBlocked() throws Exception {
			when(handlerMethod.getBeanType()).then(i -> ControllerMethodRequireRenforceCheck.class);
			when(handlerMethod.getMethod()).thenReturn(ControllerMethodRequireRenforceCheck.class.getMethod(
			        "verb"));
			when(request.getMethod()).thenReturn("GET");

			when(request.getHeader(AUTHORIZATION)).thenReturn("bearer " + token);
			loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secured"), new Date(), false);
			when(securedTokenService.loggedUserRightsExtractToken(token, false)).thenReturn(
			        loggedUserTagsDto);

			when(authenticationService.getRightsForUser(uuid, clientAddr)).thenReturn(List.of("secured"));
			when(authenticationService.isUserEnabledAndNonBlocked(uuid)).thenReturn(false);

			assertThrows(UnauthorizedRequestException.class,
			        () -> controlerInterceptor.preHandle(request, response, handlerMethod));

			verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
			verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
			verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, CLASSIC);
			verify(request, atLeastOnce()).setAttribute(USER_TOKEN_ATTRIBUTE_NAME, loggedUserTagsDto);
			verify(handlerMethod, atLeastOnce()).getBeanType();
			verify(handlerMethod, atLeastOnce()).getMethod();
			verify(authenticationService, atLeastOnce()).isUserEnabledAndNonBlocked(uuid);
		}

		@Test
		void class_badRights() throws Exception {
			when(handlerMethod.getBeanType()).then(i -> ControllerClassRequireRenforceCheck.class);
			when(handlerMethod.getMethod()).thenReturn(ControllerClassRequireRenforceCheck.class.getMethod("verb"));
			when(request.getMethod()).thenReturn("GET");

			when(request.getHeader(AUTHORIZATION)).thenReturn("bearer " + token);
			loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secured"), new Date(), false);
			when(securedTokenService.loggedUserRightsExtractToken(token, false)).thenReturn(
			        loggedUserTagsDto);

			when(authenticationService.getRightsForUser(uuid, clientAddr)).thenReturn(List.of("another"));
			when(authenticationService.isUserEnabledAndNonBlocked(uuid)).thenReturn(true);

			assertThrows(ForbiddenRequestException.class,
			        () -> controlerInterceptor.preHandle(request, response, handlerMethod));

			verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
			verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
			verify(request, atLeastOnce()).getHeader("X-Forwarded-For");
			verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, CLASSIC);
			verify(request, atLeastOnce()).setAttribute(USER_TOKEN_ATTRIBUTE_NAME, loggedUserTagsDto);
			verify(request, atLeastOnce()).getRemoteAddr();

			verify(handlerMethod, atLeastOnce()).getBeanType();
			verify(handlerMethod, atLeastOnce()).getMethod();
			verify(authenticationService, atLeastOnce()).isUserEnabledAndNonBlocked(uuid);
			verify(authenticationService, atLeastOnce()).getRightsForUser(uuid, clientAddr);
		}

		@Test
		void class_badDisabledOrBlocked() throws Exception {
			when(handlerMethod.getBeanType()).then(i -> ControllerClassRequireRenforceCheck.class);
			when(handlerMethod.getMethod()).thenReturn(ControllerClassRequireRenforceCheck.class.getMethod("verb"));
			when(request.getMethod()).thenReturn("GET");

			when(request.getHeader(AUTHORIZATION)).thenReturn("bearer " + token);
			loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secured"), new Date(), false);
			when(securedTokenService.loggedUserRightsExtractToken(token, false)).thenReturn(
			        loggedUserTagsDto);

			when(authenticationService.getRightsForUser(uuid, clientAddr)).thenReturn(List.of("secured"));
			when(authenticationService.isUserEnabledAndNonBlocked(uuid)).thenReturn(false);

			assertThrows(UnauthorizedRequestException.class,
			        () -> controlerInterceptor.preHandle(request, response, handlerMethod));

			verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
			verify(request, atLeastOnce()).getHeader(AUTHORIZATION);
			verify(request, atLeastOnce()).setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, CLASSIC);
			verify(request, atLeastOnce()).setAttribute(USER_TOKEN_ATTRIBUTE_NAME, loggedUserTagsDto);
			verify(handlerMethod, atLeastOnce()).getBeanType();
			verify(handlerMethod, atLeastOnce()).getMethod();
			verify(authenticationService, atLeastOnce()).isUserEnabledAndNonBlocked(uuid);
		}

	}
}
