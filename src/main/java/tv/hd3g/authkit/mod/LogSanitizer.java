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
package tv.hd3g.authkit.mod;

/**
 * Used for replace new lines/tabs in a String + trim.
 * @see https://sonarcloud.io/organizations/hdsdi3g/rules?open=javasecurity%3AS5145&rule_key=javasecurity%3AS5145
 */
public class LogSanitizer {

	private LogSanitizer() {
	}

	public static final String sanitize(final String value) {
		return value.replaceAll("[\n|\r|\t]", " ").trim();
	}
}
