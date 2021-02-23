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

import static tv.hd3g.authkit.utility.LogSanitizer.sanitize;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

public class AddGroupOrRoleDto {

	@NotBlank
	@Size(min = 3, max = 80)
	private String name;
	@Size(min = 0, max = 255)
	private String description;

	public String getName() {
		return sanitize(name);
	}

	public void setName(final String name) {
		this.name = name;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(final String description) {
		this.description = description;
	}

}
