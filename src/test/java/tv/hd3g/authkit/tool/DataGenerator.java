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

import static java.net.InetAddress.getByName;
import static java.time.Duration.ofDays;
import static java.util.stream.Collectors.joining;
import static java.util.stream.IntStream.range;
import static net.datafaker.Faker.instance;
import static tv.hd3g.authkit.mod.ControllerInterceptor.USER_UUID_ATTRIBUTE_NAME;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Collections;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.text.RandomStringGenerator;
import org.mockito.Mockito;

import net.datafaker.Animal;
import net.datafaker.service.RandomService;

public class DataGenerator {
	public final static RandomService random = instance().random();
	private final static Animal animal = instance().animal();
	public final static RandomStringGenerator pwdGenerator = new RandomStringGenerator.Builder().build();
	public final static Duration thirtyDays = ofDays(30);

	private static Random secureRandom;

	static {
		try {
			secureRandom = SecureRandom.getInstance("NATIVEPRNGNONBLOCKING");
		} catch (final NoSuchAlgorithmException e) {
			try {
				secureRandom = SecureRandom.getInstanceStrong();
			} catch (final NoSuchAlgorithmException e1) {
				secureRandom = ThreadLocalRandom.current();
			}
		}
	}

	public static String makeUserLogin() {
		return instance().numerify(animal.name()
		        .replaceAll(" ", "")
		        .replaceAll("-", "")
		        .replaceAll("_", "") + "######")
		        .toLowerCase();
	}

	public static String makeUserPassword() {
		final var pOrigin = pwdGenerator.generate(2, 4)
		                    + RandomStringUtils.randomAscii(2, 4)
		                    + RandomStringUtils.random(3, ",;:!?./§&\"'(-_)=")
		                    + RandomStringUtils.randomAlphabetic(2).toLowerCase()
		                    + RandomStringUtils.randomAlphabetic(2).toUpperCase();

		final var list = pOrigin.chars().mapToObj(i -> (int) i).collect(Collectors.toList());
		Collections.shuffle(list);
		final var p = list.stream().map(Character::toString).collect(Collectors.joining());

		final var i = random.nextInt(2, p.length());
		/**
		 * Insert randomly %0 up to %128 in generated password.
		 */
		return p.substring(0, i) + "%" + random.nextInt(0, 128) + "%" + random.nextInt(0, 128) + p.substring(i);
	}

	public static String makeUserBadPassword() {
		return RandomStringUtils.randomAlphabetic(4);
	}

	public static String makeRandomString() {
		return RandomStringUtils.randomAscii(5000, 10000);
	}

	public static byte[] makeRandomBytes(final int count) {
		final var secret = new byte[count];
		secureRandom.nextBytes(secret);
		return secret;
	}

	public static <T extends Enum<?>> T getRandomEnum(final Class<T> enum_class) {
		final var x = random.nextInt(enum_class.getEnumConstants().length);
		return enum_class.getEnumConstants()[x];
	}

	public static String makeRandomThing() {
		switch (random.nextInt(10)) {
		case 0:
			return instance().aviation().aircraft();
		case 1:
			return instance().app().name();
		case 2:
			return instance().commerce().material();
		case 3:
			return instance().company().name();
		case 4:
			return instance().food().dish();
		case 5:
			return instance().food().ingredient();
		case 6:
			return instance().food().fruit();
		case 7:
			return instance().food().spice();
		case 8:
			return instance().food().sushi();
		case 9:
			return instance().food().vegetable();
		default:
			return instance().food().vegetable();
		}
	}

	public static Stream<String> makeRandomThings() {
		return IntStream.range(0, DataGenerator.random.nextInt(1, 20)).mapToObj(i -> makeRandomThing()).distinct();
	}

	public static Stream<String> makeRandomLogins() {
		return IntStream.range(0, DataGenerator.random.nextInt(1, 20)).mapToObj(i -> makeUserLogin()).distinct();
	}

	public static String makeUUID() {
		return UUID.randomUUID().toString();
	}

	public static InetAddress makeRandomIPv4() {
		try {
			return getByName(random.nextInt(0, 255) + "." +
			                 random.nextInt(0, 255) + "." +
			                 random.nextInt(0, 255) + "." +
			                 random.nextInt(0, 255));
		} catch (final UnknownHostException e) {
			return null;
		}
	}

	public static InetAddress makeRandomIPv6() {
		try {
			return getByName(range(0, 8).mapToObj(i -> random.hex(4)).collect(joining(":")));
		} catch (final UnknownHostException e) {
			return null;
		}
	}

	public static void setupMock(final HttpServletRequest request) {
		setupMock(request, false, null);
	}

	public static String setupMock(final HttpServletRequest request,
	                               final boolean randomRemoteAddr,
	                               final String userUUID) {
		final String remoteAddr;
		if (randomRemoteAddr) {
			String addr;
			/**
			 * Always reject 127.* for addr
			 */
			while ((addr = random.nextInt(0, 255) + "."
			               + random.nextInt(0, 255) + "."
			               + random.nextInt(0, 255) + "."
			               + random.nextInt(0, 255)).startsWith("127.")) {
			}
			remoteAddr = addr;
		} else {
			remoteAddr = "127.0.0.1";
		}

		Mockito.when(request.getLocalAddr()).thenReturn("127.0.0.1");
		Mockito.when(request.getLocalPort()).thenReturn(80);
		Mockito.when(request.getRemoteAddr()).thenReturn(remoteAddr);
		Mockito.when(request.getRemotePort()).thenReturn(50000);
		Mockito.when(request.getContentLengthLong()).thenReturn(42L);
		Mockito.when(request.getContentType()).thenReturn("application/json");
		Mockito.when(request.getContextPath()).thenReturn("/tests");
		Mockito.when(request.getPathInfo()).thenReturn("/no-set-here");
		Mockito.when(request.getScheme()).thenReturn("http");
		Mockito.when(request.getMethod()).thenReturn("get");

		if (userUUID != null) {
			Mockito.when(request.getAttribute(USER_UUID_ATTRIBUTE_NAME)).thenReturn(userUUID);
		}
		return remoteAddr;
	}

}
