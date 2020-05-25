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

import static java.nio.charset.StandardCharsets.UTF_8;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import tv.hd3g.commons.authkit.CipherService;

/**
 * See https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
 */
@Service
public class CipherServiceImpl implements CipherService {
	private static final String SHA3_512 = "SHA3-512";

	private static Logger log = LogManager.getLogger();

	private SecureRandom random;
	private final SecretKey secretKey;
	private final int ivSize;
	private final String transformation;
	private final int gCMParameterSpecLen;

	public CipherServiceImpl(@Value("${authkit.cipher_secret}") final String base64secret,
	                         @Value("${authkit.cipher_ivsize:12}") final int ivSize,
	                         @Value("${authkit.cipher_transformation:AES/GCM/NoPadding}") final String transformation,
	                         @Value("${authkit.cipher_GCMParameterSpecLen:128}") final int gCMParameterSpecLen) throws GeneralSecurityException {
		final byte[] secret = Base64.getDecoder().decode(base64secret.getBytes());
		secretKey = new SecretKeySpec(secret, "AES");
		try {
			random = SecureRandom.getInstance("NATIVEPRNGNONBLOCKING");
		} catch (final NoSuchAlgorithmException e) {
			random = SecureRandom.getInstanceStrong();
		}

		this.ivSize = ivSize;
		this.transformation = transformation;
		this.gCMParameterSpecLen = gCMParameterSpecLen;

		log.debug(() -> "Init cipher with "
		                + "secret width=" + secret.length * 8 + " bits"
		                + ", ivSize=" + ivSize
		                + ", transformation=" + transformation
		                + ", GCMParameterSpecLen=" + gCMParameterSpecLen);

		try {
			final var v = new String(internalUnCipher(internalCipher("check".getBytes())));
			if (v.equals("check") == false) {
				throw new GeneralSecurityException("Invalid autotest result: " + v);
			}
		} catch (final GeneralSecurityException e) {
			log.error("Can't do cipher self test, check JVM setup/key configuration", e);
			throw e;
		}

		try {
			MessageDigest.getInstance(SHA3_512);
		} catch (final NoSuchAlgorithmException e) {
			log.error("Init SHA-3 digest, check JVM setup/version", e);
			throw e;
		}
	}

	@Override
	public Random getSecureRandom() {
		return random;
	}

	private byte[] internalCipher(final byte[] clearData) throws GeneralSecurityException {
		final var iv = new byte[ivSize];
		random.nextBytes(iv);
		final var cipher = Cipher.getInstance(transformation);
		final var parameterSpec = new GCMParameterSpec(gCMParameterSpecLen, iv);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
		final var cipherText = cipher.doFinal(clearData);
		Arrays.fill(clearData, (byte) 0);

		final var byteBuffer = ByteBuffer.allocate(4 + iv.length + cipherText.length);
		byteBuffer.putInt(iv.length);
		byteBuffer.put(iv);
		Arrays.fill(iv, (byte) 0);
		byteBuffer.put(cipherText);
		return byteBuffer.array();
	}

	private byte[] internalUnCipher(final byte[] rawData) throws GeneralSecurityException {
		final var byteBuffer = ByteBuffer.wrap(rawData);
		final var ivLength = byteBuffer.getInt();
		final var iv = new byte[ivLength];
		byteBuffer.get(iv);
		final var cipherText = new byte[byteBuffer.remaining()];
		byteBuffer.get(cipherText);

		final var cipher = Cipher.getInstance(transformation);
		final var parameterSpec = new GCMParameterSpec(gCMParameterSpecLen, iv);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
		return cipher.doFinal(cipherText);
	}

	@Override
	public byte[] cipherFromData(final byte[] clearData) {
		try {
			return internalCipher(clearData);
		} catch (final GeneralSecurityException e) {
			log.error("Can't do cipher operation", e);
			return new byte[0];
		}
	}

	@Override
	public byte[] unCipherToData(final byte[] rawData) {
		try {
			return internalUnCipher(rawData);
		} catch (final GeneralSecurityException e) {
			log.error("Can't do cipher operation", e);
			return new byte[0];
		}
	}

	@Override
	public byte[] cipherFromString(final String text) {
		return cipherFromData(text.getBytes(UTF_8));
	}

	@Override
	public String unCipherToString(final byte[] rawData) {
		return new String(unCipherToData(rawData), UTF_8);
	}

	public static final String byteToString(final byte[] b) {
		final StringBuilder sb = new StringBuilder();
		for (final byte element : b) {
			final int v = element & 0xFF;
			if (v < 16) {
				sb.append(0);
			}
			sb.append(Integer.toString(v, 16).toLowerCase());
		}
		return sb.toString();
	}

	@Override
	public String computeSHA3FromString(final String text) {
		try {
			final MessageDigest md = MessageDigest.getInstance(SHA3_512);
			md.update(text.getBytes(UTF_8));
			return byteToString(md.digest());
		} catch (final NoSuchAlgorithmException e) {
			return null;
		}
	}

}
