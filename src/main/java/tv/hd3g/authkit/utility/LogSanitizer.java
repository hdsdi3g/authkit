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
 * Copyright (C) hdsdi3g for hd3g.tv 2020
 *
 */
package tv.hd3g.authkit.utility;

/**
 * Used for replace new lines/tabs in a String + trim: see Sonar S5145
 */
public class LogSanitizer {

	private LogSanitizer() {
	}

	public static final String sanitize(final String value) {
		if (value == null) {
			return null;
		} else if (value.isEmpty()) {
			return "";
		}
		return value.replaceAll("[\n|\r|\t]", " ").trim();
	}
}
