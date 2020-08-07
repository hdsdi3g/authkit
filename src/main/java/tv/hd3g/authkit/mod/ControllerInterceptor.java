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
import static javax.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static tv.hd3g.authkit.mod.LogSanitizer.sanitize;
import static tv.hd3g.authkit.mod.service.AuditReportServiceImpl.getOriginalRemoteAddr;

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
import tv.hd3g.authkit.mod.component.AuthKitEndpointsListener.AnnotatedClass;
import tv.hd3g.authkit.mod.dto.LoggedUserTagsTokenDto;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException;
import tv.hd3g.authkit.mod.service.AuditReportService;
import tv.hd3g.authkit.mod.service.AuthenticationService;
import tv.hd3g.authkit.mod.service.SecuredTokenService;
import tv.hd3g.commons.authkit.AuditAfter;

public class ControllerInterceptor implements HandlerInterceptor {
	private static Logger log = LogManager.getLogger();
	public static final String USER_UUID_ATTRIBUTE_NAME = ControllerInterceptor.class.getPackageName() + ".userUUID";

	private final AuditReportService auditService;
	private final SecuredTokenService securedTokenService;
	private final AuthKitEndpointsListener authKitEndpointsListener;
	private final AuthenticationService authenticationService;

	public ControllerInterceptor(final AuditReportService auditService,
	                             final SecuredTokenService securedTokenService,
	                             final AuthKitEndpointsListener authKitEndpointsListener,
	                             final AuthenticationService authenticationService) {
		this.auditService = auditService;
		this.securedTokenService = securedTokenService;
		this.authKitEndpointsListener = authKitEndpointsListener;
		this.authenticationService = authenticationService;
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

	private Optional<LoggedUserTagsTokenDto> extractAndCheckAuthToken(final HttpServletRequest request) throws Unauthorized {
		/**
		 * Extract potential JWT
		 */
		final var oBearer = Optional.ofNullable(request.getHeader(AUTHORIZATION))
		        .filter(content -> content.toLowerCase().startsWith("bearer"))
		        .map(content -> content.substring("bearer".length()).trim());

		/**
		 * Check and parse JWT
		 */
		if (oBearer.isEmpty()) {
			return Optional.empty();
		}

		LoggedUserTagsTokenDto loggedDto;
		try {
			loggedDto = securedTokenService.loggedUserRightsExtractToken(oBearer.get());
		} catch (final NotAcceptableSecuredTokenException e) {
			throw new Unauthorized("Invalid JWT in auth request from {}", getOriginalRemoteAddr(request));
		}
		Objects.requireNonNull(loggedDto);

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
				throw new Unauthorized(
				        "Reject request for {} from {} because the actual token contain a IP restriction on {} only",
				        loggedDto.getUserUUID(),
				        getOriginalRemoteAddr(request),
				        loggedDto.getOnlyForHost());
			}
		}
		return Optional.of(loggedDto);
	}

	/**
	 * Get mandatory rights and compare with user rights
	 */
	private void compareUserRightsAndRequestMandatories(final HttpServletRequest request,
	                                                    final LoggedUserTagsTokenDto loggedUserTagsTokenDto,
	                                                    final Method classMethod,
	                                                    final AnnotatedClass annotatedClass) throws BaseInternalException {
		final var requireAuthList = annotatedClass.requireAuthList(classMethod);
		if (requireAuthList.isEmpty()) {
			return;
		}
		final var userUUID = loggedUserTagsTokenDto.getUserUUID();
		if (userUUID == null) {
			throw new Unauthorized("Unauthorized user from {}", getOriginalRemoteAddr(request));
		}

		if (requireAuthList.stream().noneMatch(
		        annotation -> stream(annotation.value()).allMatch(loggedUserTagsTokenDto.getTags()::contains))) {
			throw new Forbidden("Forbidden user {} from {} to go to {}",
			        userUUID, getOriginalRemoteAddr(request), request.getRequestURI());
		}
	}

	private void checkRenforcedRightsChecks(final HttpServletRequest request,
	                                        final AnnotatedClass annotatedClass,
	                                        final Method classMethod,
	                                        final LoggedUserTagsTokenDto tokenPayload) throws BaseInternalException {
		if (annotatedClass.isRequireRenforceCheckBefore(classMethod) == false) {
			return;
		}
		final var userUUID = tokenPayload.getUserUUID();
		if (authenticationService.isUserEnabledAndNonBlocked(userUUID) == false) {
			throw new Unauthorized("User {} is now disabled/blocked before last login", userUUID);
		}

		final var clientAddr = getOriginalRemoteAddr(request);
		final var actualTags = authenticationService.getRightsForUser(userUUID, clientAddr)
		        .stream().distinct().collect(Collectors.toUnmodifiableSet());
		for (final var tag : tokenPayload.getTags()) {
			if (actualTags.contains(tag) == false) {
				throw new Forbidden("User {} has lost some rights (like {}) before last login from {}",
				        userUUID, tag, getOriginalRemoteAddr(request));
			}
		}
	}

	@Override
	public boolean preHandle(final HttpServletRequest request,
	                         final HttpServletResponse response,
	                         final Object handler) throws IOException {
		if (isRequestIsHandle(request, handler) == false) {
			return true;
		}

		try {
			final var tokenPayload = extractAndCheckAuthToken(request)
			        .orElse(new LoggedUserTagsTokenDto(null, Set.of(), null));
			final String userUUID = tokenPayload.getUserUUID();
			request.setAttribute(USER_UUID_ATTRIBUTE_NAME, userUUID);

			final var handlerMethod = (HandlerMethod) handler;
			final var controllerClass = handlerMethod.getBeanType();
			final var annotatedClass = authKitEndpointsListener.getAnnotatedClass(controllerClass);
			final var classMethod = handlerMethod.getMethod();

			checkRenforcedRightsChecks(request, annotatedClass, classMethod, tokenPayload);
			compareUserRightsAndRequestMandatories(request, tokenPayload, classMethod, annotatedClass);

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
		} catch (final BaseInternalException e) {
			e.pushAudit(request);
			response.reset();
			response.sendError(e.statusCode);
			log.error(e.logMessage, e.logContent);
		}
		return false;
	}

	private abstract class BaseInternalException extends Exception {

		private final int statusCode;
		private final String logMessage;
		private final Object[] logContent;

		protected BaseInternalException(final int statusCode, final String logMessage, final Object[] logContent) {
			this.statusCode = statusCode;
			this.logMessage = logMessage;
			this.logContent = logContent;
		}

		protected abstract void pushAudit(HttpServletRequest request);

		/**
		 * For Sonar needs (squid:S1948)
		 */
		private void writeObject(final java.io.ObjectOutputStream out) throws IOException {
		}

		/**
		 * For Sonar needs (squid:S1948)
		 */
		private void readObject(final java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
		}
	}

	private class Unauthorized extends BaseInternalException {
		protected Unauthorized(final String logMessage, final Object... logContent) {
			super(SC_UNAUTHORIZED, logMessage, logContent);
		}

		@Override
		protected void pushAudit(final HttpServletRequest request) {
			auditService.interceptUnauthorizedRequest(request);
		}
	}

	private class Forbidden extends BaseInternalException {
		protected Forbidden(final String logMessage, final Object... logContent) {
			super(SC_FORBIDDEN, logMessage, logContent);
		}

		@Override
		protected void pushAudit(final HttpServletRequest request) {
			auditService.interceptForbiddenRequest(request);
		}
	}

	public static final Optional<String> getRequestUserUUID(final HttpServletRequest request) {
		return Optional.ofNullable(request.getAttribute(USER_UUID_ATTRIBUTE_NAME))
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
