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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static tv.hd3g.authkit.mod.ControllerInterceptor.USER_UUID_ATTRIBUTE_NAME;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomIPv4;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomString;
import static tv.hd3g.authkit.tool.DataGenerator.makeUUID;

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
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException.BadUseSecuredTokenInvalidType;
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

	@BeforeEach
	void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		DataGenerator.setupMock(request);
		clientAddr = "127.0.0.1";
		authKitEndpointsListener = new AuthKitEndpointsListener();
		controlerInterceptor = new ControllerInterceptor(
		        auditService, securedTokenService, authKitEndpointsListener, authenticationService, cookieService);
		uuid = makeUUID();
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
		verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
		verify(request, atLeastOnce()).getMethod();
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
		verify(cookieService, atLeastOnce()).getLogonCookiePayload(eq(request));
	}

	@Test
	void preHandleUserNotLogged_CtrlWithoutSecure_verbWithSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithoutSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithoutSecure.class.getMethod("verbWithSecure"));
		when(request.getMethod()).thenReturn("GET");

		assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(response, atLeastOnce()).reset();
		verify(response, atLeastOnce()).sendError(UNAUTHORIZED.value());

		verify(auditService, atLeastOnce()).interceptUnauthorizedRequest(request);

		verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
		verify(request, atLeastOnce()).getHeader(eq("X-Forwarded-For"));
		verify(request, atLeastOnce()).getRemoteAddr();
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
		verify(cookieService, atLeastOnce()).getLogonCookiePayload(eq(request));
	}

	@Test
	void preHandleUserNotLogged_CtrlWithSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(response, atLeastOnce()).reset();
		verify(response, atLeastOnce()).sendError(UNAUTHORIZED.value());

		verify(auditService, atLeastOnce()).interceptUnauthorizedRequest(request);

		verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
		verify(request, atLeastOnce()).getHeader(eq("X-Forwarded-For"));
		// verify(request, atLeastOnce()).getMethod();
		verify(request, atLeastOnce()).getRemoteAddr();
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
		verify(cookieService, atLeastOnce()).getLogonCookiePayload(eq(request));
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

		final var token = makeRandomString().replace(' ', '_');
		when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
		final var loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of(), new Date(), false);
		when(securedTokenService.loggedUserRightsExtractToken(eq(token), eq(false))).thenReturn(loggedUserTagsDto);

		assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(response, atLeastOnce()).reset();
		verify(response, atLeastOnce()).sendError(FORBIDDEN.value());

		verify(auditService, atLeastOnce()).interceptForbiddenRequest(request);

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
		verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
		verify(request, atLeastOnce()).getHeader(eq("X-Forwarded-For"));
		// verify(request, atLeastOnce()).getMethod();
		verify(request, atLeastOnce()).getRemoteAddr();
		verify(request, atLeastOnce()).getRequestURI();
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
		verify(cookieService, atLeastOnce()).getLogonCookiePayload(eq(request));
	}

	@Test
	void preHandleUserLoggedWithoutRights_CtrlWithSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		final var token = makeRandomString().replace(' ', '_');
		when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
		final var loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of(), new Date(), false);
		when(securedTokenService.loggedUserRightsExtractToken(eq(token), eq(false))).thenReturn(loggedUserTagsDto);

		/**
		 * Have some trouble with unit tests (flaky).
		 */
		assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(response, atLeastOnce()).reset();
		verify(response, atLeastOnce()).sendError(FORBIDDEN.value());
		verify(auditService, atLeastOnce()).interceptForbiddenRequest(request);

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
		verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
		verify(request, atLeastOnce()).getHeader(eq("X-Forwarded-For"));
		verify(request, atLeastOnce()).getRequestURI();
		verify(request, atLeastOnce()).getRemoteAddr();
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
		verify(cookieService, atLeastOnce()).getLogonCookiePayload(eq(request));
	}

	@Test
	void preHandleUserLoggedWithRights_CtrlWithoutSecure_verbWithSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithoutSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithoutSecure.class.getMethod("verbWithSecure"));
		when(request.getMethod()).thenReturn("GET");

		final var token = makeRandomString().replace(' ', '_');
		when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
		final var loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secureOnMethod"), new Date(), false);
		when(securedTokenService.loggedUserRightsExtractToken(eq(token), eq(false))).thenReturn(loggedUserTagsDto);

		assertTrue(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
		verify(request, atLeastOnce()).setAttribute(eq(USER_UUID_ATTRIBUTE_NAME), eq(uuid));
		verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
		verify(request, atLeastOnce()).getMethod();
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
	}

	@Test
	void preHandleUserLoggedWithRightsViaCookieOnly_RESTCtrlSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> RESTControllerWithoutSecure.class);
		when(handlerMethod.getMethod()).thenReturn(RESTControllerWithoutSecure.class.getMethod("verbWithSecure"));
		when(request.getMethod()).thenReturn("GET");

		final var token = makeRandomString().replace(' ', '_');
		when(cookieService.getLogonCookiePayload(request)).thenReturn(token);
		when(request.getHeader(eq(AUTHORIZATION))).thenReturn(null);
		final var loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secureOnMethod"), new Date(), true);
		when(securedTokenService.loggedUserRightsExtractToken(eq(token), eq(true))).thenReturn(loggedUserTagsDto);

		final var deleteCookie = Mockito.mock(Cookie.class);
		when(cookieService.deleteLogonCookie()).thenReturn(deleteCookie);

		assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(response, atLeastOnce()).reset();
		verify(response, atLeastOnce()).sendError(UNAUTHORIZED.value());
		verify(response, atLeastOnce()).addCookie(eq(deleteCookie));

		verify(auditService, atLeastOnce()).interceptUnauthorizedRequest(request);

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
		verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
		verify(request, atLeastOnce()).getHeader(eq("X-Forwarded-For"));
		verify(request, atLeastOnce()).getRemoteAddr();
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
		verify(cookieService, atLeastOnce()).getLogonCookiePayload(eq(request));
		verify(cookieService, atLeastOnce()).deleteLogonCookie();
	}

	@Test
	void preHandleUserLogged_EmptyRights_ViaCookieOnly() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> CheckWORightsCtrl.class);
		when(handlerMethod.getMethod()).thenReturn(CheckWORightsCtrl.class.getMethod("verb"));
		when(request.getMethod()).thenReturn("GET");

		final var token = makeRandomString().replace(' ', '_');
		when(cookieService.getLogonCookiePayload(request)).thenReturn(token);
		when(request.getHeader(eq(AUTHORIZATION))).thenReturn(null);
		final var loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of(), new Date(), true);
		when(securedTokenService.loggedUserRightsExtractToken(eq(token), eq(true))).thenReturn(loggedUserTagsDto);

		assertTrue(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
		verify(request, atLeastOnce()).setAttribute(eq(USER_UUID_ATTRIBUTE_NAME), eq(uuid));
		verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
		verify(request, atLeastOnce()).getMethod();
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
		verify(cookieService, atLeastOnce()).getLogonCookiePayload(eq(request));
	}

	@Test
	void preHandleUserLogged_EmptyRights_ViaBearerOnly() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> CheckWORightsRestCtrl.class);
		when(handlerMethod.getMethod()).thenReturn(CheckWORightsRestCtrl.class.getMethod("verb"));
		when(request.getMethod()).thenReturn("GET");

		final var token = makeRandomString().replace(' ', '_');
		when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
		final var loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of(), new Date(), false);
		when(securedTokenService.loggedUserRightsExtractToken(eq(token), eq(false))).thenReturn(loggedUserTagsDto);

		assertTrue(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
		verify(request, atLeastOnce()).setAttribute(eq(USER_UUID_ATTRIBUTE_NAME), eq(uuid));
		verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
		verify(request, atLeastOnce()).getMethod();
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
	}

	@Test
	void preHandleUserNotLogged_EmptyRights() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> CheckWORightsRestCtrl.class);
		when(handlerMethod.getMethod()).thenReturn(CheckWORightsRestCtrl.class.getMethod("verb"));
		when(request.getMethod()).thenReturn("GET");

		when(request.getHeader(eq(AUTHORIZATION))).thenReturn(null);

		assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(response, atLeastOnce()).reset();
		verify(response, atLeastOnce()).sendError(UNAUTHORIZED.value());

		verify(auditService, atLeastOnce()).interceptUnauthorizedRequest(request);

		verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
		verify(request, atLeastOnce()).getHeader(eq("X-Forwarded-For"));
		verify(request, atLeastOnce()).getRemoteAddr();
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
		verify(cookieService, atLeastOnce()).getLogonCookiePayload(eq(request));
	}

	@Nested
	class PreHandleUserLoggedWithRights_ViaCookieOnly {
		String token;

		@BeforeEach
		void init() throws Exception {
			when(handlerMethod.getBeanType()).then(i -> CheckClosedCtrl.class);

			token = makeRandomString().replace(' ', '_');
			when(cookieService.getLogonCookiePayload(request)).thenReturn(token);
			when(request.getHeader(eq(AUTHORIZATION))).thenReturn(null);
			final var loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secureOnClass"), new Date(), true);
			when(securedTokenService.loggedUserRightsExtractToken(eq(token), eq(true))).thenReturn(loggedUserTagsDto);
		}

		@Nested
		class Ok {

			@AfterEach
			void end() throws Exception {
				verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
				verify(request, atLeastOnce()).setAttribute(eq(USER_UUID_ATTRIBUTE_NAME), eq(uuid));
				verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
				verify(request, atLeastOnce()).getMethod();
				verify(handlerMethod, atLeastOnce()).getBeanType();
				verify(handlerMethod, atLeastOnce()).getMethod();
				verify(cookieService, atLeastOnce()).getLogonCookiePayload(eq(request));
			}

			@Test
			void get() throws Exception {
				when(handlerMethod.getMethod()).thenReturn(CheckClosedCtrl.class.getMethod("verbGET"));
				when(request.getMethod()).thenReturn("GET");

				assertTrue(controlerInterceptor.preHandle(request, response, handlerMethod));
			}

			@Test
			void post() throws Exception {
				when(handlerMethod.getMethod()).thenReturn(CheckClosedCtrl.class.getMethod("verbPOST"));
				when(request.getMethod()).thenReturn("POST");

				assertTrue(controlerInterceptor.preHandle(request, response, handlerMethod));
			}

		}

		@Nested
		class Fail {

			@Mock
			Cookie deleteCookie;

			@BeforeEach
			void init() throws Exception {
				MockitoAnnotations.openMocks(this).close();
				when(cookieService.deleteLogonCookie()).thenReturn(deleteCookie);
			}

			@Test
			void put() throws Exception {
				when(handlerMethod.getMethod()).thenReturn(CheckClosedCtrl.class.getMethod("verbPUT"));
				when(request.getMethod()).thenReturn("PUT");

				assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));
			}

			@Test
			void delete() throws Exception {
				when(handlerMethod.getMethod()).thenReturn(CheckClosedCtrl.class.getMethod("verbDELETE"));
				when(request.getMethod()).thenReturn("DELETE");

				assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));
			}

			@Test
			void patch() throws Exception {
				when(handlerMethod.getMethod()).thenReturn(CheckClosedCtrl.class.getMethod("verbPATCH"));
				when(request.getMethod()).thenReturn("PATCH");

				assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));
			}

			@AfterEach
			void end() throws Exception {
				verify(response, atLeastOnce()).reset();
				verify(response, atLeastOnce()).sendError(BAD_REQUEST.value());
				verify(response, atLeastOnce()).addCookie(eq(deleteCookie));

				verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
				verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
				verify(request, atLeastOnce()).getHeader(eq("X-Forwarded-For"));
				verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
				verify(request, atLeastOnce()).getMethod();
				verify(request, atLeastOnce()).getRemoteAddr();
				verify(request, atLeastOnce()).getRequestURI();
				verify(handlerMethod, atLeastOnce()).getBeanType();
				verify(handlerMethod, atLeastOnce()).getMethod();
				verify(cookieService, atLeastOnce()).getLogonCookiePayload(eq(request));
				verify(cookieService, atLeastOnce()).deleteLogonCookie();
				verify(deleteCookie, atLeastOnce()).setSecure(eq(true));
				Mockito.verifyNoMoreInteractions(deleteCookie);
			}
		}

	}

	@Test
	void preHandleUserLoggedWithRights_CtrlWithSecure() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		final var token = makeRandomString().replace(' ', '_');
		when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
		final var loggedUserTagsDto = new LoggedUserTagsTokenDto(
		        uuid, Set.of("secureOnClass", "secureOnMethod"), new Date(), false);
		when(securedTokenService.loggedUserRightsExtractToken(eq(token), eq(false))).thenReturn(loggedUserTagsDto);

		assertTrue(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
		verify(request, atLeastOnce()).setAttribute(eq(USER_UUID_ATTRIBUTE_NAME), eq(uuid));
		verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
		verify(request, atLeastOnce()).getMethod();
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
	}

	@Test
	void preHandleUserLoggedWithRights_InvalidRightsLinkedIP() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		final var token = makeRandomString().replace(' ', '_');
		when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
		final var loggedUserTagsDto = new LoggedUserTagsTokenDto(
		        uuid, Set.of("secureOnClass", "secureOnMethod"), new Date(), false, makeRandomIPv4()
		                .getHostAddress());
		when(securedTokenService.loggedUserRightsExtractToken(eq(token), eq(false))).thenReturn(loggedUserTagsDto);

		assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(response, atLeastOnce()).reset();
		verify(response, atLeastOnce()).sendError(UNAUTHORIZED.value());

		verify(auditService, atLeastOnce()).interceptUnauthorizedRequest(request);

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
		verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
		verify(request, atLeastOnce()).getHeader(eq("X-Forwarded-For"));
		verify(request, atLeastOnce()).getRemoteAddr();
		verify(cookieService, atLeastOnce()).getLogonCookiePayload(eq(request));
	}

	@Test
	void preHandleInvalidBearer_ButCookieLogged() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		final var token0 = makeRandomString().replace(' ', '_');
		when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token0);
		when(securedTokenService.loggedUserRightsExtractToken(eq(token0), eq(false)))
		        .thenThrow(BadUseSecuredTokenInvalidType.class);

		final var token1 = makeRandomString().replace(' ', '_');
		when(cookieService.getLogonCookiePayload(eq(request))).thenReturn(token1);
		final var loggedUserTagsDto1 = new LoggedUserTagsTokenDto(
		        uuid, Set.of("secureOnClass", "secureOnMethod"), new Date(), true);
		when(securedTokenService.loggedUserRightsExtractToken(eq(token1), eq(true))).thenReturn(loggedUserTagsDto1);

		final var deleteCookie = Mockito.mock(Cookie.class);
		when(cookieService.deleteLogonCookie()).thenReturn(deleteCookie);

		assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(response, atLeastOnce()).reset();
		verify(response, atLeastOnce()).sendError(UNAUTHORIZED.value());
		verify(response, atLeastOnce()).addCookie(eq(deleteCookie));

		verify(auditService, atLeastOnce()).interceptUnauthorizedRequest(request);

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token0), anyBoolean());
		verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
		verify(request, atLeastOnce()).getHeader(eq("X-Forwarded-For"));
		verify(request, atLeastOnce()).getRemoteAddr();
		verify(cookieService, atLeastOnce()).getLogonCookiePayload(eq(request));
		verify(cookieService, atLeastOnce()).deleteLogonCookie();
	}

	@Test
	void preHandleUserLoggedWithRights_ValidRightsLinkedIP() throws Exception {
		when(handlerMethod.getBeanType()).then(i -> ControllerWithSecure.class);
		when(handlerMethod.getMethod()).thenReturn(ControllerWithSecure.class.getMethod("verbWithoutSecure"));
		when(request.getMethod()).thenReturn("GET");

		final var token = makeRandomString().replace(' ', '_');
		when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
		final var loggedUserTagsDto = new LoggedUserTagsTokenDto(
		        uuid, Set.of("secureOnClass", "secureOnMethod"), new Date(), false, request.getRemoteAddr());
		when(securedTokenService.loggedUserRightsExtractToken(eq(token), eq(false))).thenReturn(loggedUserTagsDto);

		assertTrue(controlerInterceptor.preHandle(request, response, handlerMethod));

		verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
		verify(request, atLeastOnce()).setAttribute(eq(USER_UUID_ATTRIBUTE_NAME), eq(uuid));
		verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
		verify(request, atLeastOnce()).getHeader(eq("X-Forwarded-For"));
		verify(request, atLeastOnce()).getMethod();
		verify(request, atLeastOnce()).getRemoteAddr();
		verify(handlerMethod, atLeastOnce()).getBeanType();
		verify(handlerMethod, atLeastOnce()).getMethod();
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

			final var token = makeRandomString().replace(' ', '_');
			when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
			final var loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secured"), new Date(), false);
			when(securedTokenService.loggedUserRightsExtractToken(eq(token), eq(false))).thenReturn(
			        loggedUserTagsDto);

			when(authenticationService.getRightsForUser(eq(uuid), eq(clientAddr))).thenReturn(List.of("another"));
			when(authenticationService.isUserEnabledAndNonBlocked(eq(uuid))).thenReturn(true);

			assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

			verify(response, atLeastOnce()).reset();
			verify(response, atLeastOnce()).sendError(FORBIDDEN.value());
			verify(auditService, atLeastOnce()).interceptForbiddenRequest(request);

			verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
			verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
			verify(request, atLeastOnce()).getHeader(eq("X-Forwarded-For"));
			verify(request, atLeastOnce()).getRemoteAddr();
			verify(handlerMethod, atLeastOnce()).getBeanType();
			verify(handlerMethod, atLeastOnce()).getMethod();
			verify(authenticationService, atLeastOnce()).isUserEnabledAndNonBlocked(eq(uuid));
			verify(authenticationService, atLeastOnce()).getRightsForUser(eq(uuid), eq(clientAddr));
			verify(cookieService, atLeastOnce()).getLogonCookiePayload(eq(request));
		}

		@Test
		void method_badDisabledOrBlocked() throws Exception {
			when(handlerMethod.getBeanType()).then(i -> ControllerMethodRequireRenforceCheck.class);
			when(handlerMethod.getMethod()).thenReturn(ControllerMethodRequireRenforceCheck.class.getMethod(
			        "verb"));
			when(request.getMethod()).thenReturn("GET");

			final var token = makeRandomString().replace(' ', '_');
			when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
			final var loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secured"), new Date(), false);
			when(securedTokenService.loggedUserRightsExtractToken(eq(token), eq(false))).thenReturn(
			        loggedUserTagsDto);

			when(authenticationService.getRightsForUser(eq(uuid), eq(clientAddr))).thenReturn(List.of("secured"));
			when(authenticationService.isUserEnabledAndNonBlocked(eq(uuid))).thenReturn(false);

			assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

			verify(response, atLeastOnce()).reset();
			verify(response, atLeastOnce()).sendError(UNAUTHORIZED.value());

			verify(auditService, atLeastOnce()).interceptUnauthorizedRequest(request);

			verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
			verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
			verify(handlerMethod, atLeastOnce()).getBeanType();
			verify(handlerMethod, atLeastOnce()).getMethod();
			verify(authenticationService, atLeastOnce()).isUserEnabledAndNonBlocked(eq(uuid));
			verify(cookieService, atLeastOnce()).getLogonCookiePayload(eq(request));
		}

		@Test
		void class_badRights() throws Exception {
			when(handlerMethod.getBeanType()).then(i -> ControllerClassRequireRenforceCheck.class);
			when(handlerMethod.getMethod()).thenReturn(ControllerClassRequireRenforceCheck.class.getMethod("verb"));
			when(request.getMethod()).thenReturn("GET");

			final var token = makeRandomString().replace(' ', '_');
			when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
			final var loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secured"), new Date(), false);
			when(securedTokenService.loggedUserRightsExtractToken(eq(token), eq(false))).thenReturn(
			        loggedUserTagsDto);

			when(authenticationService.getRightsForUser(eq(uuid), eq(clientAddr))).thenReturn(List.of("another"));
			when(authenticationService.isUserEnabledAndNonBlocked(eq(uuid))).thenReturn(true);

			assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

			verify(response, atLeastOnce()).reset();
			verify(response, atLeastOnce()).sendError(FORBIDDEN.value());

			verify(auditService, atLeastOnce()).interceptForbiddenRequest(request);

			verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
			verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
			verify(request, atLeastOnce()).getHeader(eq("X-Forwarded-For"));
			verify(request, atLeastOnce()).getRemoteAddr();
			verify(handlerMethod, atLeastOnce()).getBeanType();
			verify(handlerMethod, atLeastOnce()).getMethod();
			verify(authenticationService, atLeastOnce()).isUserEnabledAndNonBlocked(eq(uuid));
			verify(authenticationService, atLeastOnce()).getRightsForUser(eq(uuid), eq(clientAddr));
			verify(cookieService, atLeastOnce()).getLogonCookiePayload(eq(request));
		}

		@Test
		void class_badDisabledOrBlocked() throws Exception {
			when(handlerMethod.getBeanType()).then(i -> ControllerClassRequireRenforceCheck.class);
			when(handlerMethod.getMethod()).thenReturn(ControllerClassRequireRenforceCheck.class.getMethod("verb"));
			when(request.getMethod()).thenReturn("GET");

			final var token = makeRandomString().replace(' ', '_');
			when(request.getHeader(eq(AUTHORIZATION))).thenReturn("bearer " + token);
			final var loggedUserTagsDto = new LoggedUserTagsTokenDto(uuid, Set.of("secured"), new Date(), false);
			when(securedTokenService.loggedUserRightsExtractToken(eq(token), eq(false))).thenReturn(
			        loggedUserTagsDto);

			when(authenticationService.getRightsForUser(eq(uuid), eq(clientAddr))).thenReturn(List.of("secured"));
			when(authenticationService.isUserEnabledAndNonBlocked(eq(uuid))).thenReturn(false);

			assertFalse(controlerInterceptor.preHandle(request, response, handlerMethod));

			verify(response, atLeastOnce()).reset();
			verify(response, atLeastOnce()).sendError(UNAUTHORIZED.value());

			verify(auditService, atLeastOnce()).interceptUnauthorizedRequest(request);

			verify(securedTokenService, atLeastOnce()).loggedUserRightsExtractToken(eq(token), anyBoolean());
			verify(request, atLeastOnce()).getHeader(eq(AUTHORIZATION));
			verify(handlerMethod, atLeastOnce()).getBeanType();
			verify(handlerMethod, atLeastOnce()).getMethod();
			verify(authenticationService, atLeastOnce()).isUserEnabledAndNonBlocked(eq(uuid));
			verify(cookieService, atLeastOnce()).getLogonCookiePayload(eq(request));
		}

	}
}
