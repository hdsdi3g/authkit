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

import static java.time.Duration.ZERO;
import static java.util.stream.Collectors.toUnmodifiableSet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static tv.hd3g.authkit.mod.service.AuditReportServiceImpl.EVENTNAME_CHANGE_SECURITY;
import static tv.hd3g.authkit.mod.service.AuditReportServiceImpl.EVENTNAME_ERROR;
import static tv.hd3g.authkit.mod.service.AuditReportServiceImpl.EVENTNAME_FORBIDDEN_REQUEST;
import static tv.hd3g.authkit.mod.service.AuditReportServiceImpl.EVENTNAME_LOGIN;
import static tv.hd3g.authkit.mod.service.AuditReportServiceImpl.EVENTNAME_REJECT_LOGIN;
import static tv.hd3g.authkit.mod.service.AuditReportServiceImpl.EVENTNAME_REPORT;
import static tv.hd3g.authkit.mod.service.AuditReportServiceImpl.EVENTNAME_SIMPLE_EVENT;
import static tv.hd3g.authkit.mod.service.AuditReportServiceImpl.EVENTNAME_UNAUTHORIZED_REQUEST;
import static tv.hd3g.authkit.mod.service.AuditReportServiceImpl.EVENTNAME_USE_SECURITY;
import static tv.hd3g.authkit.tool.DataGenerator.getRandomEnum;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomLogins;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomThing;
import static tv.hd3g.authkit.tool.DataGenerator.makeUUID;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserLogin;

import java.time.Duration;
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import tv.hd3g.authkit.mod.entity.Audit;
import tv.hd3g.authkit.mod.repository.AuditRepository;
import tv.hd3g.authkit.mod.service.AuditReportService.RejectLoginCause;
import tv.hd3g.authkit.tool.DataGenerator;

@SpringBootTest
class AuditReportServiceTest {

	private static final Duration ONE_MINUTE = Duration.ofMinutes(1);

	@Autowired
	private AuditReportService auditReportService;
	@Autowired
	private AuditRepository auditRepository;
	@Value("${authkit.audit.appname:authkit}")
	private String appname;
	@Value("${authkit.realm}")
	private String realm;

	@Mock
	private HttpServletRequest request;
	private String clientsourcehost;
	private String userUUID;

	@BeforeEach
	void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		userUUID = makeUUID();
		clientsourcehost = DataGenerator.setupMock(request, true, userUUID);
	}

	private Audit postChecks(final String eventref, final String expectedEventName) {
		auditRepository.flush();
		final var audit = auditRepository.getByEventref(eventref);
		assertNotNull(audit);
		if (expectedEventName.equals(EVENTNAME_UNAUTHORIZED_REQUEST)) {
			assertNull(audit.getUseruuid());
		} else {
			assertNotNull(audit.getUseruuid());
		}
		assertEquals(appname, audit.getAppname());
		assertEquals(clientsourcehost, audit.getClientsourcehost());
		assertEquals(expectedEventName, audit.getEventname());
		return audit;
	}

	@Test
	void testInterceptUnauthorizedRequest() {
		final var eventref = auditReportService.interceptUnauthorizedRequest(request);
		postChecks(eventref, EVENTNAME_UNAUTHORIZED_REQUEST);
	}

	@Test
	void testInterceptForbiddenRequest() {
		final var eventref = auditReportService.interceptForbiddenRequest(request);
		postChecks(eventref, EVENTNAME_FORBIDDEN_REQUEST);
	}

	@Test
	void testOnImportantError() {
		final var thing = DataGenerator.makeRandomThing();
		final var eventref = auditReportService.onImportantError(
		        request, List.of(), new Exception("Normal test error : " + thing));
		final var audit = postChecks(eventref, EVENTNAME_ERROR);
		assertNotNull(audit.getTriggeredexception());
		assertTrue(audit.getTriggeredexception().contains(thing));
	}

	@Test
	void testOnUseSecurity() {
		final var eventref = auditReportService.onUseSecurity(request, List.of());
		postChecks(eventref, EVENTNAME_USE_SECURITY);
	}

	@Test
	void testOnChangeSecurity() {
		final var eventref = auditReportService.onChangeSecurity(request, List.of());
		postChecks(eventref, EVENTNAME_CHANGE_SECURITY);
	}

	@Test
	void testOnSimpleEvent() {
		final var eventref = auditReportService.onSimpleEvent(request, List.of());
		postChecks(eventref, EVENTNAME_SIMPLE_EVENT);
	}

	@Test
	void testOnRejectLogin() {
		final var rejectLoginCause = getRandomEnum(RejectLoginCause.class);
		final var what = makeRandomThing();
		final var eventref = auditReportService.onRejectLogin(request, rejectLoginCause, realm, what);
		final var audit = postChecks(eventref, EVENTNAME_REJECT_LOGIN);

		assertNotNull(audit.getContext());
		assertTrue(audit.getContext().contains(rejectLoginCause.toString()));
		assertTrue(audit.getContext().contains(what));
		assertTrue(audit.getContext().contains(realm));
	}

	@Test
	void testOnLogin() {
		final var tags = makeRandomLogins().collect(toUnmodifiableSet());
		final var eventref = auditReportService.onLogin(request, ZERO, tags);
		final var audit = postChecks(eventref, EVENTNAME_LOGIN);

		assertNotNull(audit.getContext());
		for (final var tag : tags) {
			assertTrue(audit.getContext().contains(tag));
		}
	}

	@Test
	void testOnReport() {
		final var reportName = makeRandomThing();
		final var subject = makeRandomThing();
		final var eventref = auditReportService.onReport(request, reportName, subject, ZERO);
		final var audit = postChecks(eventref, EVENTNAME_REPORT);
		assertNotNull(audit.getContext());
		assertTrue(audit.getContext().contains(reportName));
		assertTrue(audit.getContext().contains(subject));
	}

	@Test
	void testReportLastUserActivities() {
		final var list1 = auditReportService.reportLastUserActivities(request, userUUID, ONE_MINUTE);
		assertNotNull(list1);
		assertTrue(list1.isEmpty());

		auditReportService.onSimpleEvent(request, List.of());
		auditReportService.onUseSecurity(request, List.of());
		auditReportService.onChangeSecurity(request, List.of());

		auditRepository.flush();
		final var list2 = auditReportService.reportLastUserActivities(request, userUUID, ONE_MINUTE);
		assertNotNull(list2);
		assertEquals(4, list2.size());

		assertTrue(list2.stream().anyMatch(a -> a.getEventname().equals(EVENTNAME_REPORT)));
		assertTrue(list2.stream().anyMatch(a -> a.getEventname().equals(EVENTNAME_SIMPLE_EVENT)));
		assertTrue(list2.stream().anyMatch(a -> a.getEventname().equals(EVENTNAME_USE_SECURITY)));
		assertTrue(list2.stream().anyMatch(a -> a.getEventname().equals(EVENTNAME_CHANGE_SECURITY)));
	}

	@Test
	void testReportLastRemoteIPActivity() {
		final var list1 = auditReportService.reportLastRemoteIPActivity(request, clientsourcehost, ONE_MINUTE);
		assertNotNull(list1);
		assertTrue(list1.isEmpty());

		auditReportService.onSimpleEvent(request, List.of());
		auditReportService.onUseSecurity(request, List.of());
		auditReportService.onChangeSecurity(request, List.of());

		auditRepository.flush();
		final var list2 = auditReportService.reportLastRemoteIPActivity(request, clientsourcehost, ONE_MINUTE);
		assertNotNull(list2);
		assertEquals(4, list2.size());

		assertTrue(list2.stream().anyMatch(a -> a.getEventname().equals(EVENTNAME_REPORT)));
		assertTrue(list2.stream().anyMatch(a -> a.getEventname().equals(EVENTNAME_SIMPLE_EVENT)));
		assertTrue(list2.stream().anyMatch(a -> a.getEventname().equals(EVENTNAME_USE_SECURITY)));
		assertTrue(list2.stream().anyMatch(a -> a.getEventname().equals(EVENTNAME_CHANGE_SECURITY)));
	}

	@Test
	void testReportLastEventActivity() {
		final var eventRef = auditReportService.onSimpleEvent(request, List.of());
		auditRepository.flush();

		final var list1 = auditReportService.reportLastEventActivity(request, EVENTNAME_SIMPLE_EVENT, ONE_MINUTE);
		assertNotNull(list1);
		assertFalse(list1.isEmpty());
		assertTrue(list1.stream().anyMatch(a -> a.getEventref().equals(eventRef)));
	}

	@Test
	void testReportAllEventNames() {
		auditReportService.onReport(request, makeRandomThing(), makeRandomThing(), ZERO);
		auditReportService.onLogin(request, ZERO, Set.of());
		auditReportService.onRejectLogin(request, RejectLoginCause.USER_NOT_FOUND, makeUserLogin(), makeRandomThing());
		auditReportService.onSimpleEvent(request, List.of());
		auditReportService.onUseSecurity(request, List.of());
		auditReportService.onChangeSecurity(request, List.of());
		auditReportService.onImportantError(request, List.of(), new Exception("Nothing grave, only for tests"));
		auditReportService.interceptForbiddenRequest(request);
		auditReportService.interceptUnauthorizedRequest(request);

		final var names = auditReportService.reportAllEventNames(request);
		auditRepository.flush();

		assertTrue(names.contains(EVENTNAME_REPORT));
		assertTrue(names.contains(EVENTNAME_LOGIN));
		assertTrue(names.contains(EVENTNAME_REJECT_LOGIN));
		assertTrue(names.contains(EVENTNAME_SIMPLE_EVENT));
		assertTrue(names.contains(EVENTNAME_USE_SECURITY));
		assertTrue(names.contains(EVENTNAME_CHANGE_SECURITY));
		assertTrue(names.contains(EVENTNAME_ERROR));
		assertTrue(names.contains(EVENTNAME_FORBIDDEN_REQUEST));
		assertTrue(names.contains(EVENTNAME_UNAUTHORIZED_REQUEST));
	}

	@Test
	void testReportLastClientsourcehosts() {
		auditReportService.onSimpleEvent(request, List.of());
		auditRepository.flush();

		final var list1 = auditReportService.reportLastClientsourcehosts(request, ONE_MINUTE);
		assertNotNull(list1);
		assertTrue(list1.contains(clientsourcehost));
	}

}
