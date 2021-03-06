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

import static tv.hd3g.authkit.mod.ControllerInterceptor.getRequestUserUUID;
import static tv.hd3g.authkit.utility.LogSanitizer.sanitize;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import tv.hd3g.authkit.mod.entity.Audit;
import tv.hd3g.authkit.mod.repository.AuditRepository;

@Service
@Transactional(readOnly = false)
public class AuditReportServiceImpl implements AuditReportService {
	private static final Logger log = LogManager.getLogger();

	public static final String EVENTNAME_REPORT = "Report";
	public static final String EVENTNAME_LOGIN = "Login";
	public static final String EVENTNAME_REJECT_LOGIN = "RejectLogin";
	public static final String EVENTNAME_SIMPLE_EVENT = "SimpleEvent";
	public static final String EVENTNAME_USE_SECURITY = "UseSecurity";
	public static final String EVENTNAME_CHANGE_SECURITY = "ChangeSecurity";
	public static final String EVENTNAME_ERROR = "Error";
	public static final String EVENTNAME_FORBIDDEN_REQUEST = "ForbiddenRequest";
	public static final String EVENTNAME_UNAUTHORIZED_REQUEST = "UnauthorizedRequest";

	@Autowired
	private AuditRepository auditRepository;

	@Value("${authkit.audit.appname:authkit}")
	private String appname;

	public static String getOriginalRemoteAddr(final HttpServletRequest request) {
		return Optional.ofNullable(request.getHeader("X-Forwarded-For"))
		        .map(proxyReturn -> Arrays.stream(proxyReturn.split(",")).findFirst().get().trim())
		        .orElse(request.getRemoteAddr());
	}

	private static String getFullURLQuery(final HttpServletRequest request) {
		final var queryString = Optional.ofNullable(request.getQueryString()).map(qs -> "?" + qs).orElse("");
		return sanitize(request.getContextPath() + request.getRequestURI() + queryString);
	}

	private Audit prepareAudit(final HttpServletRequest request, final String eventName) {
		final var clientsourcehost = getOriginalRemoteAddr(request);
		final var requestcontenttype = Optional.ofNullable(request.getContentType()).orElse("null/null");
		final var requestlength = request.getContentLengthLong();

		return new Audit(appname, UUID.randomUUID().toString(),
		        clientsourcehost, request.getRemotePort(),
		        request.getLocalAddr(), request.getLocalPort(),
		        eventName, request.getScheme(), request.getMethod(),
		        getFullURLQuery(request),
		        requestcontenttype, requestlength);
	}

	@Override
	public String interceptUnauthorizedRequest(final HttpServletRequest request) {
		log.info("Audit unauthorized from {} in {}", getOriginalRemoteAddr(request), getFullURLQuery(request));
		return auditRepository.save(prepareAudit(request, EVENTNAME_UNAUTHORIZED_REQUEST)).getEventref();
	}

	@Override
	public String interceptForbiddenRequest(final HttpServletRequest request) {
		final var userUUID = getRequestUserUUID(request).orElse(null);
		log.info("Audit forbiddenRequestException from {} in {} by {}", getOriginalRemoteAddr(request), getFullURLQuery(
		        request), userUUID);
		final var audit = prepareAudit(request, EVENTNAME_FORBIDDEN_REQUEST);
		audit.setUseruuid(userUUID);
		return auditRepository.save(audit).getEventref();
	}

	private static void setAuditNames(final Audit audit, final List<String> names) {
		audit.setContext(names.stream().collect(Collectors.joining(", ")));
	}

	@Override
	public String onImportantError(final HttpServletRequest request,
	                               final List<String> names,
	                               final Exception e) {
		final var userUUID = getRequestUserUUID(request).orElse(null);
		log.info("Audit error from {} in {} by {} [{}]",
		        getOriginalRemoteAddr(request), getFullURLQuery(request), userUUID, names, e);

		final var audit = prepareAudit(request, EVENTNAME_ERROR);
		audit.setUseruuid(userUUID);
		final var fullStack = ExceptionUtils.getStackTrace(e);
		if (fullStack.length() > 255) {
			audit.setTriggeredexception(fullStack.substring(0, 252) + "...");
		} else {
			audit.setTriggeredexception(fullStack);
		}
		setAuditNames(audit, names);
		return auditRepository.save(audit).getEventref();
	}

	@Override
	public String onChangeSecurity(final HttpServletRequest request, final List<String> names) {
		final var userUUID = getRequestUserUUID(request).orElse(null);
		log.info("Audit change security from {} in {} by {} [{}]",
		        getOriginalRemoteAddr(request), getFullURLQuery(request), userUUID, names);
		final var audit = prepareAudit(request, EVENTNAME_CHANGE_SECURITY);
		audit.setUseruuid(userUUID);
		setAuditNames(audit, names);
		return auditRepository.save(audit).getEventref();
	}

	@Override
	public String onUseSecurity(final HttpServletRequest request, final List<String> names) {
		final var userUUID = getRequestUserUUID(request).orElse(null);
		log.info("Audit use security from {} in {} by {} [{}]",
		        getOriginalRemoteAddr(request), getFullURLQuery(request), userUUID, names);
		final var audit = prepareAudit(request, EVENTNAME_USE_SECURITY);
		audit.setUseruuid(userUUID);
		setAuditNames(audit, names);
		return auditRepository.save(audit).getEventref();
	}

	@Override
	public String onSimpleEvent(final HttpServletRequest request, final List<String> names) {
		final var userUUID = getRequestUserUUID(request).orElse(null);
		log.info("Audit simple event from {} in {} by {} [{}]",
		        getOriginalRemoteAddr(request), getFullURLQuery(request), userUUID, names);
		final var audit = prepareAudit(request, EVENTNAME_SIMPLE_EVENT);
		audit.setUseruuid(userUUID);
		setAuditNames(audit, names);
		return auditRepository.save(audit).getEventref();
	}

	@Override
	public String onRejectLogin(final HttpServletRequest request,
	                            final RejectLoginCause cause,
	                            final String realm,
	                            final String what) {
		final var userUUID = getRequestUserUUID(request).orElse(null);
		log.info("Audit rejeted login from {} in {} by {}/{} {}",
		        getOriginalRemoteAddr(request), getFullURLQuery(request), userUUID, realm, what);

		final var audit = prepareAudit(request, EVENTNAME_REJECT_LOGIN);
		audit.setUseruuid(userUUID);
		audit.setContext(cause.toString() + ": " + what + " (realm: " + realm + ")");
		return auditRepository.save(audit).getEventref();
	}

	@Override
	public String onLogin(final HttpServletRequest request,
	                      final Duration longSessionDuration,
	                      final Set<String> tags) {
		final var userUUID = getRequestUserUUID(request).orElse(null);
		log.info("Audit login from {} in {} by {}, with rights {}, during {}",
		        getOriginalRemoteAddr(request),
		        getFullURLQuery(request),
		        userUUID,
		        tags,
		        longSessionDuration);

		final var audit = prepareAudit(request, EVENTNAME_LOGIN);
		audit.setUseruuid(userUUID);
		audit.setContext(" during " + longSessionDuration + " with tags: " +
		                 tags.stream().collect(Collectors.joining(", ")));
		return auditRepository.save(audit).getEventref();
	}

	@Override
	public String onReport(final HttpServletRequest request,
	                       final String reportName,
	                       final String subject,
	                       final Duration sinceTime) {
		final var userUUID = getRequestUserUUID(request).orElse(null);
		final var audit = prepareAudit(request, EVENTNAME_REPORT);
		audit.setUseruuid(userUUID);
		audit.setContext("Make report " + reportName + " on: " + subject + " last events, since " + sinceTime);
		return auditRepository.save(audit).getEventref();
	}

	private static final Date getDateFromTimeAgo(final Duration sinceTime) {
		return new Date(System.currentTimeMillis() - sinceTime.toMillis());
	}

	@Override
	public Collection<Audit> reportLastUserActivities(final HttpServletRequest originalRequest,
	                                                  final String userUUID,
	                                                  final Duration sinceTime) {
		final var result = auditRepository.getByUserUUID(userUUID, getDateFromTimeAgo(sinceTime));
		onReport(originalRequest, "ReportLastUserActivities", userUUID, sinceTime);
		return result;
	}

	@Override
	public Collection<Audit> reportLastRemoteIPActivity(final HttpServletRequest originalRequest,
	                                                    final String address,
	                                                    final Duration sinceTime) {
		final var result = auditRepository.getByClientsourcehost(
		        address, getDateFromTimeAgo(sinceTime));
		onReport(originalRequest, "ReportLastRemoteIPActivity", address, sinceTime);
		return result;
	}

	@Override
	public Collection<Audit> reportLastEventActivity(final HttpServletRequest originalRequest,
	                                                 final String eventName,
	                                                 final Duration sinceTime) {
		final var result = auditRepository.getByEventname(eventName, getDateFromTimeAgo(sinceTime));
		onReport(originalRequest, "ReportLastEventActivity", eventName, sinceTime);
		return result;
	}

	@Override
	public Collection<String> reportAllEventNames(final HttpServletRequest originalRequest) {
		final var result = auditRepository.getAllEventnames();
		onReport(originalRequest, "ReportAllEventNames", "", Duration.ZERO);
		return result;
	}

	@Override
	public Collection<String> reportLastClientsourcehosts(final HttpServletRequest originalRequest,
	                                                      final Duration sinceTime) {
		final var result = auditRepository.getLastClientsourcehosts(getDateFromTimeAgo(sinceTime));
		onReport(originalRequest, "ReportLastEventsInetAddress", "", sinceTime);
		return result;
	}
}
