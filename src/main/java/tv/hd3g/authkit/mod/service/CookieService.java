/*
 * This file is part of authkit.
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
 * Copyright (C) hdsdi3g for hd3g.tv 2021
 *
 */
package tv.hd3g.authkit.mod.service;

import java.time.Duration;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

public interface CookieService {

	String AUTH_COOKIE_NAME = "SESSIONBEARER";
	String REDIRECT_AFTER_LOGIN_COOKIE_NAME = "REDIRECTAFTERLOGIN";

	Cookie createLogonCookie(String userSessionToken, Duration ttl);

	Cookie deleteLogonCookie();

	String getLogonCookiePayload(HttpServletRequest request);

	Cookie createRedirectAfterLoginCookie(String path);

	Cookie deleteRedirectAfterLoginCookie();

	String getRedirectAfterLoginCookiePayload(HttpServletRequest request);

}
