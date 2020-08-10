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
package tv.hd3g.authkit.mod.dto.ressource;

import java.net.URI;
import java.util.List;
import java.util.Objects;

import org.springframework.hateoas.RepresentationModel;

public class SetupTOTPDto extends RepresentationModel<SetupTOTPDto> {

	private final String secret;
	private final URI totpURI;
	private final String qrcode;
	private final List<String> backupCodes;
	private final String jwtControl;

	public SetupTOTPDto(final String secret,
	                    final URI totpURI,
	                    final String qrcode,
	                    final List<String> backupCodes,
	                    final String jwtControl) {
		this.secret = secret;
		this.totpURI = totpURI;
		this.qrcode = qrcode;
		this.backupCodes = backupCodes;
		this.jwtControl = jwtControl;
	}

	@Override
	public int hashCode() {
		final var prime = 31;
		var result = super.hashCode();
		result = prime * result + Objects.hash(backupCodes, qrcode, secret, totpURI, jwtControl);
		return result;
	}

	@Override
	public boolean equals(final Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final var other = (SetupTOTPDto) obj;
		return Objects.equals(backupCodes, other.backupCodes) && Objects.equals(qrcode, other.qrcode)
		       && Objects.equals(secret, other.secret) && Objects.equals(totpURI, other.totpURI)
		       && Objects.equals(jwtControl, other.jwtControl);
	}

	public String getSecret() {
		return secret;
	}

	public URI getTotpURI() {
		return totpURI;
	}

	public String getQrcode() {
		return qrcode;
	}

	public List<String> getBackupCodes() {
		return backupCodes;
	}

	public String getJwtControl() {
		return jwtControl;
	}
}
