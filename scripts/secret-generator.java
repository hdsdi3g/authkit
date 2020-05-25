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
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Usage:
 * $ java secret-generator.java
 */
public class SecretGenerator {

	public static final String BASE_FILENAME_OUT = "secret-application.yml";

	private static Random random;
	private static Encoder base64e = Base64.getEncoder();

	static {
		try {
			random = SecureRandom.getInstance("NATIVEPRNGNONBLOCKING");
		} catch (final NoSuchAlgorithmException e) {
			try {
				random = SecureRandom.getInstanceStrong();
			} catch (final NoSuchAlgorithmException e1) {
				random = ThreadLocalRandom.current();
			}
		}
	}

	/**
	 * See https://dev.to/keysh/spring-security-with-jwt-3j76
	 *      Use on-the-fly for generate valid keys.
	 */
	public static void main(String[] args) throws IOException{
		final File outFile = new File(BASE_FILENAME_OUT);
		try (final PrintWriter pw = new PrintWriter(outFile)) {
			pw.println("# Random generated keys for authkit configuration (base 64 encoded):");
			pw.println("authkit:");
			pw.println("    jwt_secret: \"" + generate(128) + "\"");
			pw.println("    cipher_secret: \"" + generate(32) + "\"");
			pw.println("# Copy these tree lines on all app instances \"application.yml\" configuration files.");
			pw.println("# Never share these values outside app instances!");
		}
		System.out.println("Secrets writed on file " + outFile.getAbsolutePath());
	}

	/**
	 * @return base64 coded String
	 */
	private static String generate(final int size) {
		final byte[] generatedKey = new byte[size];
		random.nextBytes(generatedKey);
		return new String(base64e.encode(generatedKey));
	}
}
