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

import static tv.hd3g.authkit.mod.ControllerInterceptor.CONTROLLER_TYPE_ATTRIBUTE_NAME;
import static tv.hd3g.authkit.mod.ControllerInterceptor.getUserTokenFromRequestAttribute;
import static tv.hd3g.authkit.mod.service.AuditReportServiceImpl.getOriginalRemoteAddr;
import static tv.hd3g.authkit.utility.ControllerType.CLASSIC;
import static tv.hd3g.authkit.utility.ControllerType.REST;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.SimpleMappingExceptionResolver;

import tv.hd3g.authkit.mod.exception.SecurityRejectedRequestException;
import tv.hd3g.authkit.mod.exception.UnauthorizedRequestException;
import tv.hd3g.authkit.mod.service.AuditReportService;
import tv.hd3g.authkit.mod.service.CookieService;
import tv.hd3g.authkit.utility.ControllerType;

public class SecurityRejectedRequestMappingExceptionResolver extends SimpleMappingExceptionResolver {
	private static final Logger log = LogManager.getLogger();

	private final AuditReportService auditService;
	private final CookieService cookieService;
	private final String authErrorViewName;

	public SecurityRejectedRequestMappingExceptionResolver(final AuditReportService auditService,
	                                                       final CookieService cookieService,
	                                                       final String authErrorViewName) {
		this.auditService = auditService;
		this.cookieService = cookieService;
		this.authErrorViewName = authErrorViewName;
	}

	@Override
	protected ModelAndView doResolveException(final HttpServletRequest request,
	                                          final HttpServletResponse response,
	                                          final Object handler,
	                                          final Exception e) {
		final var controllerTypeObject = request.getAttribute(CONTROLLER_TYPE_ATTRIBUTE_NAME);
		if (controllerTypeObject == null) {
			if (log.isTraceEnabled()) {
				log.trace("{} request exception ({}) is not managed here (controllerType is not set)",
				        request.getRequestURI(), e.getClass());
			}
			return null;
		} else if (e instanceof SecurityRejectedRequestException == false) {
			if (log.isTraceEnabled()) {
				log.trace("{} request exception ({}) is not managed here",
				        request.getRequestURI(), e.getClass());
			}
			return null;
		}

		final var controllerType = (ControllerType) controllerTypeObject;
		final var requestException = (SecurityRejectedRequestException) e;
		final var statusCode = requestException.getStatusCode();

		final var addr = getOriginalRemoteAddr(request);
		final var userUUID = requestException.getUserUUID();
		if (userUUID != null) {
			log.warn("[{} {}] {}; {}", addr, request.getRequestURI(), e.getMessage(), userUUID);
		} else {
			log.warn("[{} {}] {}", addr, request.getRequestURI(), e.getMessage());
		}

		requestException.pushAudit(auditService, request);

		if (controllerType == CLASSIC) {
			if (requestException instanceof UnauthorizedRequestException) {
				final var redirectURL = removeSpecialChars(request.getRequestURI()
				                                           + Optional.ofNullable(request.getQueryString())
				                                                   .map("?"::concat)
				                                                   .orElse(""));
				final var cookieRedirect = cookieService.createRedirectAfterLoginCookie(redirectURL);
				cookieRedirect.setSecure(true);
				response.addCookie(cookieRedirect);
			}

			final var mav = new ModelAndView(authErrorViewName);
			mav.addObject("cause", statusCode.value());
			mav.addObject("requestURL", request.getRequestURL().toString());
			mav.addObject("isnotlogged", getUserTokenFromRequestAttribute(request).isEmpty());
			mav.setStatus(statusCode);
			return mav;
		} else if (controllerType == REST) {
			try {
				response.sendError(statusCode.value());
			} catch (final IOException e1) {
				log.error("Can't send error response", e1);
			}
		}
		return new ModelAndView();
	}

	static String removeSpecialChars(final String str) {
		final var sb = new StringBuilder();
		for (var pos = 0; pos < str.length(); pos++) {
			final var currChar = str.codePointAt(pos);
			if (Character.isSpaceChar(currChar) || Character.isWhitespace(currChar)) {
				continue;
			}
			sb.append(str.charAt(pos));
		}
		return sb.toString();
	}

}
