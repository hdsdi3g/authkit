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

import java.util.Objects;

import org.springframework.hateoas.RepresentationModel;

import tv.hd3g.authkit.mod.entity.Credential;

public class IsTOTPEnabledDto extends RepresentationModel<IsTOTPEnabledDto> {

	private final boolean twoAuthEnabled;

	public IsTOTPEnabledDto(final Credential credential) {
		twoAuthEnabled = credential.getTotpkey() != null;
	}

	public boolean isTwoAuthEnabled() {
		return twoAuthEnabled;
	}

	@Override
	public int hashCode() {
		final var prime = 31;
		var result = super.hashCode();
		result = prime * result + Objects.hash(twoAuthEnabled);
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
		final var other = (IsTOTPEnabledDto) obj;
		return twoAuthEnabled == other.twoAuthEnabled;
	}

}
