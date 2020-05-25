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
package tv.hd3g.authkit.mod.dto.validated;

import javax.validation.constraints.NotEmpty;

public class ValidationSetupTOTPDto extends ValidationTOTPDto {

	@NotEmpty
	private String controlToken;

	public String getControlToken() {
		return controlToken;
	}

	public void setControlToken(final String controlToken) {
		this.controlToken = controlToken;
	}
}
