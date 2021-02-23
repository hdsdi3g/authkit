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
package tv.hd3g.authkit.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomIPv4;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomIPv6;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CIDRUtilsTest {

	String ipv4;
	String ipv6;
	InetAddress addrv4;
	InetAddress addrv6;

	@BeforeEach
	void init() {
		addrv4 = makeRandomIPv4();
		addrv6 = makeRandomIPv6();
		ipv4 = addrv4.getHostAddress();
		ipv6 = addrv6.getHostAddress();
	}

	@Test
	void testCIDRUtils_v4() throws UnknownHostException {
		new CIDRUtils(ipv4 + "/1");
		new CIDRUtils(ipv4 + "/24");
		new CIDRUtils(ipv4 + "/32");
		new CIDRUtils(ipv4 + "/0");
		assertThrows(IllegalArgumentException.class, () -> new CIDRUtils(ipv4 + "/5555"));
		assertThrows(IllegalArgumentException.class, () -> new CIDRUtils(ipv4 + "/-1"));
		assertThrows(IllegalArgumentException.class, () -> new CIDRUtils(ipv4 + "/"));
		assertThrows(UnknownHostException.class, () -> new CIDRUtils("[" + ipv4 + "]/5"));
		assertThrows(IllegalArgumentException.class, () -> new CIDRUtils(ipv4));
		assertThrows(IllegalArgumentException.class, () -> new CIDRUtils(ipv4 + "/55/55"));
	}

	@Test
	void testCIDRUtils_v6() throws UnknownHostException {
		new CIDRUtils(ipv6 + "/1");
		new CIDRUtils(ipv6 + "/64");
		new CIDRUtils(ipv6 + "/128");
		new CIDRUtils(ipv6 + "/0");
		assertThrows(IllegalArgumentException.class, () -> new CIDRUtils(ipv6 + "/5555"));
		assertThrows(IllegalArgumentException.class, () -> new CIDRUtils(ipv6 + "/-1"));
		assertThrows(IllegalArgumentException.class, () -> new CIDRUtils(ipv6 + "/"));
		new CIDRUtils("[" + ipv6 + "]/5");
		new CIDRUtils("::5" + "/5");
		new CIDRUtils("5::" + "/5");
		assertThrows(UnknownHostException.class, () -> new CIDRUtils("[::5::]/5"));
		assertThrows(IllegalArgumentException.class, () -> new CIDRUtils(ipv6));
		assertThrows(IllegalArgumentException.class, () -> new CIDRUtils(ipv6 + "/55/55"));
	}

	@Test
	void testCIDRUtils_InetAddressInt_v4() throws UnknownHostException {
		new CIDRUtils(addrv4, 1);
		new CIDRUtils(addrv4, 24);
		new CIDRUtils(addrv4, 32);
		new CIDRUtils(addrv4, 0);
		assertThrows(IllegalArgumentException.class, () -> new CIDRUtils(addrv4, 5555));
		assertThrows(IllegalArgumentException.class, () -> new CIDRUtils(addrv4, -1));
	}

	@Test
	void testCIDRUtils_InetAddressInt_v6() throws UnknownHostException {
		new CIDRUtils(addrv6, 1);
		new CIDRUtils(addrv6, 64);
		new CIDRUtils(addrv6, 128);
		new CIDRUtils(addrv6, 0);
		assertThrows(IllegalArgumentException.class, () -> new CIDRUtils(addrv6, 5555));
		assertThrows(IllegalArgumentException.class, () -> new CIDRUtils(addrv6, -1));
	}

	@Test
	void testGetNetworkAddress_v4() throws UnknownHostException {
		final var c = new CIDRUtils(InetAddress.getByName("192.168.0.1"), 24);
		assertEquals("192.168.0.0", c.getNetworkAddress());
	}

	@Test
	void testGetNetworkAddress_v6() throws UnknownHostException {
		final var c = new CIDRUtils(InetAddress.getByName("::1"), 64);
		assertEquals("0:0:0:0:0:0:0:0", c.getNetworkAddress());
	}

	@Test
	void testGetBroadcastAddress_v4() throws UnknownHostException {
		final var c = new CIDRUtils(InetAddress.getByName("192.168.0.1"), 24);
		assertEquals("192.168.0.255", c.getBroadcastAddress());
	}

	@Test
	void testGetBroadcastAddress_v6() throws UnknownHostException {
		final var c = new CIDRUtils(InetAddress.getByName("::1"), 64);
		assertEquals("0:0:0:0:ffff:ffff:ffff:ffff", c.getBroadcastAddress());
	}

	@Test
	void testIsInRange_v4() throws UnknownHostException {
		final var c = new CIDRUtils(InetAddress.getByName("192.168.0.1"), 24);
		assertTrue(c.isInRange("192.168.0.50"));
		assertFalse(c.isInRange("192.168.1.50"));
	}

	@Test
	void testIsInRange_v6() throws UnknownHostException {
		final var c = new CIDRUtils(InetAddress.getByName("::1"), 64);
		assertTrue(c.isInRange("0:0:0:0:0:ffff:ffff:ffff"));
		assertFalse(c.isInRange("0:0:0:1:ffff:ffff:ffff:ffff"));
	}

	@Test
	void testIsInRangeInetAddress_v4() throws UnknownHostException {
		final var c = new CIDRUtils(InetAddress.getByName("192.168.0.1"), 24);
		assertTrue(c.isInRange(InetAddress.getByName("192.168.0.50")));
		assertFalse(c.isInRange(InetAddress.getByName("192.168.1.50")));
	}

	@Test
	void testIsInRangeInetAddress_v6() throws UnknownHostException {
		final var c = new CIDRUtils(InetAddress.getByName("::1"), 64);
		assertTrue(c.isInRange(InetAddress.getByName("0:0:0:0:0:ffff:ffff:ffff")));
		assertFalse(c.isInRange(InetAddress.getByName("0:0:0:1:ffff:ffff:ffff:ffff")));
	}
}
