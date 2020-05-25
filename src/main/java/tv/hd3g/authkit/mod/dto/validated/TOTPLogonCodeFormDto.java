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
import javax.validation.constraints.Pattern;

public class TOTPLogonCodeFormDto {

	/**
	 * Only 6 digits
	 */
	@Pattern(regexp = "[\\d]{6}")
	private String code;
	@NotEmpty
	private String securetoken;
	/**
	 * Short time session
	 */
	private Boolean shorttime;

	public String getSecuretoken() {
		return securetoken;
	}

	public void setSecuretoken(final String securetoken) {
		this.securetoken = securetoken;
	}

	public String getCode() {
		return code;
	}

	public void setCode(final String code) {
		this.code = code;
	}

	/**
	 * @return can be null
	 */
	public Boolean getShorttime() {
		return shorttime;
	}

	public void setShorttime(final Boolean shorttime) {
		this.shorttime = shorttime;
	}

}
