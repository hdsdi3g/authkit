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
package tv.hd3g.authkit.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static tv.hd3g.authkit.utility.ControllerType.CLASSIC;
import static tv.hd3g.authkit.utility.ControllerType.REST;

import java.lang.reflect.Method;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import tv.hd3g.authkit.dummy.controller.CheckClosedCtrl;
import tv.hd3g.authkit.dummy.controller.CheckOpenCtrl;

class AnnotatedControllerClassTest {

	AnnotatedControllerClass annotatedControllerClass;

	@Nested
	class TestCheckClosedCtrl {

		Method method;

		@BeforeEach
		void init() throws Exception {
			annotatedControllerClass = new AnnotatedControllerClass(CheckClosedCtrl.class);
			method = CheckClosedCtrl.class.getMethod("verb");
		}

		@Test
		void testGetRequireAuthList() {
			final var authList = annotatedControllerClass.getRequireAuthList(method);
			assertNotNull(authList);
			assertEquals(3, authList.size());
			assertEquals("secureOnClass", authList.get(0).value()[0]);
			assertEquals("secureOnMethodOr1", authList.get(1).value()[0]);
			assertEquals("secureOnMethodOr2", authList.get(2).value()[0]);
		}

		@Test
		void testGetAudits() {
			final var audits = annotatedControllerClass.getAudits(method);
			assertNotNull(audits);
			assertEquals(3, audits.size());
			assertEquals("OnClass", audits.get(0).value());
			assertEquals("combinated1", audits.get(1).value());
			assertEquals("combinated2", audits.get(2).value());
		}

		@Test
		void testIsRequireRenforceCheckBefore() {
			assertTrue(annotatedControllerClass.isRequireRenforceCheckBefore(method));
		}

		@Test
		void testIsRequireValidAuth() {
			assertTrue(annotatedControllerClass.isRequireValidAuth(method));
		}

		@Test
		void testGetControllerType() {
			assertEquals(CLASSIC, annotatedControllerClass.getControllerType());
		}

		@Test
		void testGetAllRights() {
			assertEquals(Set.of("secureOnClass", "secureOnMethodOr1", "secureOnMethodOr2"),
			        annotatedControllerClass.getAllRights().collect(Collectors.toSet()));
		}
	}

	@Nested
	class TestCheckOpenCtrl {

		Method method;

		@BeforeEach
		void init() throws Exception {
			annotatedControllerClass = new AnnotatedControllerClass(CheckOpenCtrl.class);
			method = CheckOpenCtrl.class.getMethod("verb");
		}

		@Test
		void testGetRequireAuthList() {
			final var authList = annotatedControllerClass.getRequireAuthList(method);
			assertNotNull(authList);
			assertEquals(0, authList.size());
		}

		@Test
		void testGetAudits() {
			final var audits = annotatedControllerClass.getAudits(method);
			assertNotNull(audits);
			assertEquals(0, audits.size());
		}

		@Test
		void testIsRequireRenforceCheckBefore() {
			assertFalse(annotatedControllerClass.isRequireRenforceCheckBefore(method));
		}

		@Test
		void testIsRequireValidAuth() {
			assertFalse(annotatedControllerClass.isRequireValidAuth(method));
		}

		@Test
		void testGetControllerType() {
			assertEquals(REST, annotatedControllerClass.getControllerType());
		}

		@Test
		void testGetAllRights() {
			assertEquals(Set.of("secureOnMethodOr1", "secureOnMethodOr2"),
			        annotatedControllerClass.getAllRights().collect(Collectors.toSet()));
		}

	}
}
