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
package tv.hd3g.authkit.tool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public abstract class HashCodeEqualsTest {// NOSONAR

	protected abstract Object[] makeSameInstances();

	@Test
	void testHashCode() {
		final var instances = makeSameInstances();
		assertNotNull(instances);
		assertTrue(instances.length > 1);

		for (final Object instance : instances) {
			assertNotNull(instance);
		}
		for (int j = 1; j < instances.length; j++) {
			assertEquals(instances[0].hashCode(), instances[j].hashCode());
		}
	}

	@Test
	void testEquals() {
		final var instances = makeSameInstances();
		assertNotNull(instances);
		assertTrue(instances.length > 1);

		for (final Object instance : instances) {
			assertNotNull(instance);
		}
		assertEquals(instances, instances);
	}

	static class OppositeTest {

		@Test
		void testHashCode() {
			final var instances = new Object[] { new Object(), new Object() };
			assertNotEquals(instances[0].hashCode(), instances[1].hashCode());
		}

		@Test
		void testEquals() {
			final var instances = new Object[] { new Object(), new Object() };
			assertNotEquals(instances[0], instances[1]);
		}

	}

}
