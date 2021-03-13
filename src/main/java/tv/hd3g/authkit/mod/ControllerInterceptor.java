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

import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toUnmodifiableSet;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static tv.hd3g.authkit.mod.service.AuditReportServiceImpl.getOriginalRemoteAddr;
import static tv.hd3g.authkit.utility.LogSanitizer.sanitize;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.resource.ResourceHttpRequestHandler;

import tv.hd3g.authkit.mod.component.AuthKitEndpointsListener;
import tv.hd3g.authkit.mod.dto.LoggedUserTagsTokenDto;
import tv.hd3g.authkit.mod.exception.BadRequestException;
import tv.hd3g.authkit.mod.exception.ForbiddenRequestException;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException;
import tv.hd3g.authkit.mod.exception.UnauthorizedRequestException;
import tv.hd3g.authkit.mod.service.AuditReportService;
import tv.hd3g.authkit.mod.service.AuthenticationService;
import tv.hd3g.authkit.mod.service.CookieService;
import tv.hd3g.authkit.mod.service.SecuredTokenService;
import tv.hd3g.authkit.utility.AnnotatedControllerClass;
import tv.hd3g.authkit.utility.ControllerType;
import tv.hd3g.commons.authkit.AuditAfter;

public class ControllerInterceptor implements HandlerInterceptor {
	private static final Logger log = LogManager.getLogger();
	private static final String PACKAGE_NAME = ControllerInterceptor.class.getPackageName();
	public static final String USER_UUID_ATTRIBUTE_NAME = PACKAGE_NAME + ".userUUID";
	public static final String USER_TOKEN_ATTRIBUTE_NAME = PACKAGE_NAME + ".LoggedUserTagsToken";
	public static final String CONTROLLER_TYPE_ATTRIBUTE_NAME = PACKAGE_NAME + ".controllerType";
	public static final String REDIRECT_AFTER_LOGIN_ATTRIBUTE_NAME = PACKAGE_NAME + ".redirectAfterLogin";

	private final AuditReportService auditService;
	private final SecuredTokenService securedTokenService;
	private final AuthKitEndpointsListener authKitEndpointsListener;
	private final AuthenticationService authenticationService;
	private final CookieService cookieService;

	public ControllerInterceptor(final AuditReportService auditService,
	                             final SecuredTokenService securedTokenService,
	                             final AuthKitEndpointsListener authKitEndpointsListener,
	                             final AuthenticationService authenticationService,
	                             final CookieService cookieService) {
		this.auditService = auditService;
		this.securedTokenService = securedTokenService;
		this.authKitEndpointsListener = authKitEndpointsListener;
		this.authenticationService = authenticationService;
		this.cookieService = cookieService;
	}

	private boolean isRequestIsHandle(final HttpServletRequest request, final Object handler) {
		if (handler instanceof ResourceHttpRequestHandler) {
			final var httpHandler = (ResourceHttpRequestHandler) handler;
			Optional.ofNullable(httpHandler.getUrlPathHelper())
			        .map(uph -> uph.getLookupPathForRequest(request))
			        .ifPresent(h -> log.trace("HandlerH: {}", h));
			return false;
		} else if (handler instanceof HandlerMethod == false) {
			log.info("Unknown handler: {}", handler.getClass());
			return false;
		}
		return true;
	}

	private Optional<LoggedUserTagsTokenDto> extractAndCheckAuthToken(final HttpServletRequest request) {
		/**
		 * Extract potential JWT
		 */
		Optional<String> oBearer = Optional.ofNullable(request.getHeader(AUTHORIZATION))
		        .filter(content -> content.toLowerCase().startsWith("bearer"))
		        .map(content -> content.substring("bearer".length()).trim());

		var fromCookie = false;
		if (oBearer.isEmpty()) {
			oBearer = Optional.ofNullable(cookieService.getLogonCookiePayload(request));
			fromCookie = true;
		}

		/**
		 * Check and parse JWT
		 */
		if (oBearer.isEmpty()) {
			return Optional.empty();
		}

		LoggedUserTagsTokenDto loggedDto;
		try {
			loggedDto = Objects.requireNonNull(securedTokenService
			        .loggedUserRightsExtractToken(oBearer.get(), fromCookie));
		} catch (final NotAcceptableSecuredTokenException e) {
			throw new UnauthorizedRequestException("Invalid JWT in auth request");
		}

		/**
		 * Check if in same host as token
		 */
		if (loggedDto.getOnlyForHost() != null) {
			InetAddress addr1;
			InetAddress addr2;
			try {
				addr1 = InetAddress.getByName(loggedDto.getOnlyForHost());
				addr2 = InetAddress.getByName(getOriginalRemoteAddr(request));
			} catch (final UnknownHostException e) {
				addr1 = null;
				addr2 = null;
			}
			if (addr1 == null || addr1.equals(addr2) == false) {
				throw new UnauthorizedRequestException(
				        "Reject request for from " + loggedDto.getOnlyForHost()
				                                       + " because the actual token contain a IP restriction on {} only",
				        loggedDto.getUserUUID());
			}
		}
		return Optional.ofNullable(loggedDto);
	}

	/**
	 * Get mandatory rights and compare with user rights
	 */
	private void compareUserRightsAndRequestMandatories(final HttpServletRequest request,
	                                                    final LoggedUserTagsTokenDto loggedUserTagsTokenDto,
	                                                    final Method classMethod,
	                                                    final AnnotatedControllerClass annotatedControllerClass) {
		final var requireAuthList = annotatedControllerClass.getRequireAuthList(classMethod);
		if (requireAuthList.isEmpty()
		    && annotatedControllerClass.isRequireValidAuth(classMethod) == false) {
			/**
			 * Absolutely no auth required here
			 */
			return;
		}

		if (loggedUserTagsTokenDto.isFromCookie()) {
			if (annotatedControllerClass.getControllerType().equals(ControllerType.REST)) {
				throw new UnauthorizedRequestException("An auth cookie can't authorized a REST request");
			}
			final var requestVerb = request.getMethod();
			if (requestVerb.equalsIgnoreCase("GET") == false && requestVerb.equalsIgnoreCase("POST") == false) {
				throw new BadRequestException("Unacceptable method " + requestVerb);
			}
		}

		final var userUUID = loggedUserTagsTokenDto.getUserUUID();
		if (userUUID == null) {
			throw new UnauthorizedRequestException("Unauthorized");
		}

		if (requireAuthList.stream().noneMatch(
		        annotation -> stream(annotation.value()).allMatch(loggedUserTagsTokenDto.getTags()::contains))) {
			throw new ForbiddenRequestException("Forbidden user", userUUID);
		}
	}

	private void checkRenforcedRightsChecks(final HttpServletRequest request,
	                                        final AnnotatedControllerClass annotatedControllerClass,
	                                        final Method classMethod,
	                                        final LoggedUserTagsTokenDto tokenPayload) {
		if (annotatedControllerClass.isRequireRenforceCheckBefore(classMethod) == false) {
			return;
		}
		final var userUUID = tokenPayload.getUserUUID();
		if (authenticationService.isUserEnabledAndNonBlocked(userUUID) == false) {
			throw new UnauthorizedRequestException("User {} is now disabled/blocked before last login", userUUID);
		}

		final var clientAddr = getOriginalRemoteAddr(request);
		final var actualTags = authenticationService.getRightsForUser(userUUID, clientAddr)
		        .stream().distinct().collect(toUnmodifiableSet());
		for (final var tag : tokenPayload.getTags()) {
			if (actualTags.contains(tag) == false) {
				throw new ForbiddenRequestException("User has lost some rights (like " + tag + ") before last login",
				        userUUID);
			}
		}
	}

	@Override
	public boolean preHandle(final HttpServletRequest request, // NOSONAR S3516
	                         final HttpServletResponse response,
	                         final Object handler) throws IOException {
		if (isRequestIsHandle(request, handler) == false) {
			return true;
		}

		final var handlerMethod = (HandlerMethod) handler;
		final var controllerClass = handlerMethod.getBeanType();
		final var annotatedClass = authKitEndpointsListener.getAnnotatedClass(controllerClass);
		final var classMethod = handlerMethod.getMethod();
		request.setAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME, annotatedClass.getControllerType());

		final var oTokenPayload = extractAndCheckAuthToken(request);
		if (oTokenPayload.isPresent()) {
			request.setAttribute(USER_TOKEN_ATTRIBUTE_NAME, oTokenPayload.get());
		}

		final var tokenPayload = oTokenPayload.orElse(new LoggedUserTagsTokenDto(null, Set.of(), null, false));

		checkRenforcedRightsChecks(request, annotatedClass, classMethod, tokenPayload);
		compareUserRightsAndRequestMandatories(request, tokenPayload, classMethod, annotatedClass);

		final var userUUID = tokenPayload.getUserUUID();
		request.setAttribute(USER_UUID_ATTRIBUTE_NAME, userUUID);

		Optional.ofNullable(cookieService.getRedirectAfterLoginCookiePayload(request))
		        .ifPresent(redirectTo -> request.setAttribute(REDIRECT_AFTER_LOGIN_ATTRIBUTE_NAME, redirectTo));

		if (userUUID == null) {
			log.info("Request {} {}:{}()",
			        controllerClass.getSimpleName(),
			        request.getMethod(),
			        handlerMethod.getMethod().getName());
		} else {
			log.info("Request {} {}:{}() {}",
			        controllerClass.getSimpleName(),
			        request.getMethod(),
			        handlerMethod.getMethod().getName(),
			        userUUID);
		}

		return true;
	}

	public static final Optional<String> getRequestUserUUID(final HttpServletRequest request) {
		return Optional.ofNullable(request.getAttribute(USER_UUID_ATTRIBUTE_NAME))
		        .map(o -> sanitize((String) o));
	}

	public static final Optional<LoggedUserTagsTokenDto> getUserTokenFromRequestAttribute(final HttpServletRequest request) {
		return Optional.ofNullable(request.getAttribute(USER_TOKEN_ATTRIBUTE_NAME))
		        .map(LoggedUserTagsTokenDto.class::cast);
	}

	public static final Optional<String> getPathToRedirectToAfterLogin(final HttpServletRequest request) {
		return Optional.ofNullable(request.getAttribute(REDIRECT_AFTER_LOGIN_ATTRIBUTE_NAME))
		        .map(o -> sanitize((String) o));
	}

	@Override
	public void afterCompletion(final HttpServletRequest request,
	                            final HttpServletResponse response,
	                            final Object handler,
	                            final Exception exception) throws Exception {

		if (handler instanceof HandlerMethod == false) {
			return;
		}

		final var handlerMethod = (HandlerMethod) handler;
		final var controllerClass = handlerMethod.getBeanType();
		final var annotatedClass = authKitEndpointsListener.getAnnotatedClass(controllerClass);
		final var classMethod = handlerMethod.getMethod();
		final var auditList = annotatedClass.getAudits(classMethod);

		if (auditList.isEmpty()) {
			return;
		}

		Optional.ofNullable(exception).ifPresent(e -> {
			final var names = auditList.stream()
			        .filter(AuditAfter::cantDoErrors)
			        .map(AuditAfter::value)
			        .collect(Collectors.toUnmodifiableList());
			if (names.isEmpty() == false) {
				auditService.onImportantError(request, names, e);
			}
		});

		final var namesChangeSecurity = auditList.stream()
		        .filter(AuditAfter::changeSecurity)
		        .map(AuditAfter::value)
		        .collect(Collectors.toUnmodifiableList());
		if (namesChangeSecurity.isEmpty() == false) {
			auditService.onChangeSecurity(request, namesChangeSecurity);
		}

		final var namesUseSecurity = auditList.stream()
		        .filter(AuditAfter::useSecurity)
		        .map(AuditAfter::value)
		        .collect(Collectors.toUnmodifiableList());
		if (namesUseSecurity.isEmpty() == false) {
			auditService.onUseSecurity(request, namesUseSecurity);
		}

		final var namesSimpleAudit = auditList.stream()
		        .filter(audit -> audit.cantDoErrors() == false
		                         && audit.changeSecurity() == false
		                         && audit.useSecurity() == false)
		        .map(AuditAfter::value)
		        .collect(Collectors.toUnmodifiableList());
		if (namesSimpleAudit.isEmpty() == false) {
			auditService.onSimpleEvent(request, namesSimpleAudit);
		}
	}

}
