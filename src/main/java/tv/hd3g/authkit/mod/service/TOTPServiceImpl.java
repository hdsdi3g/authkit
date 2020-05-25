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

import static javax.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static org.apache.commons.lang3.StringUtils.leftPad;
import static org.owasp.encoder.Encode.forJavaScript;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import tv.hd3g.authkit.mod.dto.SetupTOTPTokenDto;
import tv.hd3g.authkit.mod.dto.validated.ValidationSetupTOTPDto;
import tv.hd3g.authkit.mod.dto.validated.ValidationTOTPDto;
import tv.hd3g.authkit.mod.entity.Credential;
import tv.hd3g.authkit.mod.entity.Totpbackupcode;
import tv.hd3g.authkit.mod.entity.User;
import tv.hd3g.authkit.mod.exception.AuthKitException;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.BadTOTPCodeCantLoginException;
import tv.hd3g.authkit.mod.repository.CredentialRepository;
import tv.hd3g.authkit.mod.repository.TotpbackupcodeRepository;
import tv.hd3g.commons.authkit.CipherService;

@Service
public class TOTPServiceImpl implements TOTPService {
	private static Logger log = LogManager.getLogger();

	public static final Base32 base32 = new Base32(false);

	@Autowired
	private CipherService cipherService;
	@Autowired
	private CredentialRepository credentialRepository;
	@Autowired
	private TotpbackupcodeRepository totpbackupcodeRepository;
	@Autowired
	private AuthenticationService authenticationService;
	@Autowired
	private SecuredTokenService securedTokenService;

	@Value("${authkit.backupCodeQuantity:6}")
	private int backupCodeQuantity;
	@Value("${authkit.totpTimeStepSeconds:30}")
	private int timeStepSeconds;
	@Value("${authkit.totpWindowMillis:5000}")
	private long windowMillis;

	/**
	 * @return base32 coded
	 */
	@Override
	public String makeSecret() {
		final byte[] secret = new byte[64];
		final var random = cipherService.getSecureRandom();
		random.nextBytes(secret);
		return base32.encodeAsString(secret);
	}

	@Override
	public URI makeURI(final String secret, final User user, final String totpDomain) {
		final var credential = user.getCredential();
		Objects.requireNonNull(credential, "Can't found Credential for user " + user.getUuid());
		final var login = credential.getLogin();
		try {
			return new URI("otpauth://totp/" + login + "@" + forJavaScript(totpDomain) + "?secret=" + secret);
		} catch (final URISyntaxException e) {
			throw new IllegalArgumentException("Invalid URI parameters", e);
		}
	}

	/**
	 * @return base64 coded
	 */
	@Override
	public String makeQRCode(final URI url) {
		try {
			final int size = 400;
			final BitMatrix bitMatrix = new QRCodeWriter().encode(url.toString(), BarcodeFormat.QR_CODE, size, size);
			final ByteArrayOutputStream byteArrayQRCodePNG = new ByteArrayOutputStream(0xFFF);
			MatrixToImageWriter.writeToStream(bitMatrix, "png", byteArrayQRCodePNG);
			return Base64.getEncoder().encodeToString(byteArrayQRCodePNG.toByteArray());
		} catch (final IOException | WriterException e) {
			throw new IllegalArgumentException("Problem with QRcode generation", e);
		}
	}

	@Override
	public List<String> makeBackupCodes() {
		return cipherService.getSecureRandom().ints(backupCodeQuantity, 0, 1_000_000)
		        .mapToObj(i -> leftPad(String.valueOf(i), 6, "0"))
		        .collect(Collectors.toUnmodifiableList());
	}

	@Override
	@Transactional(readOnly = false)
	public void setupTOTP(final String base32Secret, final Collection<String> backupCodes, final String userUUID) {
		final var secret = base32.decode(base32Secret);
		final var credential = credentialRepository.getByUserUUID(userUUID);
		credential.getTotpBackupCodes().clear();
		final var newCodes = backupCodes.stream()
		        .map(code -> new Totpbackupcode(credential, code))
		        .collect(Collectors.toUnmodifiableSet());
		credential.getTotpBackupCodes().addAll(newCodes);
		credential.setTotpkey(cipherService.cipherFromData(secret));
	}

	@Override
	@Transactional(readOnly = false)
	public void setupTOTPWithChecks(final ValidationSetupTOTPDto setupDto, final String expectedUserUUID) {
		final SetupTOTPTokenDto validatedToken;
		try {
			validatedToken = securedTokenService.setupTOTPExtractToken(setupDto.getControlToken());
		} catch (final NotAcceptableSecuredTokenException e) {
			log.error("Invalid token", e);
			throw new AuthKitException("You can't use this token");
		}
		if (expectedUserUUID.equalsIgnoreCase(validatedToken.getUserUUID()) == false) {
			throw new AuthKitException("You can't use this token for this user");
		}

		final var secret = base32.decode(validatedToken.getSecret());
		if (isCodeIsValid(secret, setupDto.getTwoauthcode()) == false) {
			throw new AuthKitException("Invalid code");
		}

		final var credential = credentialRepository.getByUserUUID(expectedUserUUID);
		final var rejected = authenticationService.checkPassword(setupDto.getCurrentpassword(), credential);
		if (rejected.isPresent()) {
			throw new AuthKitException(SC_UNAUTHORIZED,
			        "Can't accept demand, bad password ; " + rejected.get().toString());
		}
		setupTOTP(validatedToken.getSecret(), validatedToken.getBackupCodes(), expectedUserUUID);
	}

	private boolean isCodeIsValid(final byte[] secret, final String code) {
		try {
			final var now = System.currentTimeMillis();
			final var actualCode = makeCodeAtTime(secret, now, timeStepSeconds);
			if (actualCode.equals(code)) {
				return true;
			}
			final var previousCode = makeCodeAtTime(secret, now - windowMillis, timeStepSeconds);
			if (previousCode.equals(code)) {
				return true;
			}
			final var nextCode = makeCodeAtTime(secret, now + windowMillis, timeStepSeconds);
			if (nextCode.equals(code)) {
				return true;
			}
		} catch (final GeneralSecurityException e) {
			throw new AuthKitException(SC_INTERNAL_SERVER_ERROR, "Can't manage cipher tools");
		}
		return false;
	}

	@Override
	@Transactional(readOnly = true)
	public void checkCodeAndPassword(final Credential credential, final ValidationTOTPDto validationDto) {
		final var optPassword = authenticationService.checkPassword(validationDto.getCurrentpassword(), credential);
		if (optPassword.isPresent()) {
			throw new AuthKitException(SC_UNAUTHORIZED, "Invalid password: " + optPassword.get());
		}
		try {
			checkCode(credential, validationDto.getTwoauthcode());
		} catch (final BadTOTPCodeCantLoginException e) {
			throw new AuthKitException(SC_UNAUTHORIZED, "Invalid 2auth code");
		}
	}

	@Override
	@Transactional(readOnly = false)
	public void checkCode(final Credential credential, final String stringCode) throws BadTOTPCodeCantLoginException {
		final var secret = cipherService.unCipherToData(credential.getTotpkey());
		if (isCodeIsValid(secret, stringCode) == false) {
			final var bcpCode = totpbackupcodeRepository.getByCredential(credential).stream()
			        .filter(bcp -> bcp.getCode().equals(stringCode))
			        .findFirst()
			        .orElseThrow(BadTOTPCodeCantLoginException::new);
			totpbackupcodeRepository.delete(bcpCode);
		}
	}

	@Override
	@Transactional(readOnly = false)
	public void removeTOTP(final Credential credential) {
		credential.setTotpkey(null);
		credentialRepository.save(credential);
		totpbackupcodeRepository.getByCredential(credential).forEach(bcp -> totpbackupcodeRepository.delete(bcp));
	}

	/**
	 * See https://github.com/j256/two-factor-auth/blob/master/src/main/java/com/j256/twofactorauth/TimeBasedOneTimePasswordUtil.java
	 */
	public static String makeCodeAtTime(final byte[] secret,
	                                    final long timeMillis,
	                                    final int timeStepSeconds) throws GeneralSecurityException {
		final byte[] data = new byte[8];
		long value = timeMillis / 1000 / timeStepSeconds;
		for (int i = 7; value > 0; i--) {
			data[i] = (byte) (value & 0xFF);
			value >>= 8;
		}

		final SecretKeySpec signKey = new SecretKeySpec(secret, "HmacSHA1");
		final Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(signKey);
		final byte[] hash = mac.doFinal(data);

		final int offset = hash[hash.length - 1] & 0xF;

		long truncatedHash = 0;
		for (int i = offset; i < offset + 4; ++i) {
			truncatedHash <<= 8;
			truncatedHash |= hash[i] & 0xFF;
		}
		truncatedHash &= 0x7FFFFFFF;
		truncatedHash %= 1000000;
		return leftPad(String.valueOf((int) truncatedHash), 6, "0");
	}

}
