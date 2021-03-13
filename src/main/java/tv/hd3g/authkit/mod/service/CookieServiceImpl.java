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

import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.stream.Stream;

import javax.annotation.PostConstruct;
import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class CookieServiceImpl implements CookieService {

	@Autowired
	private ServletContext servletContext;
	@Value("${authkit.cookie.domain:}")
	private String domain;
	@Value("${authkit.cookie.path:#{servletContext.contextPath}}")
	private String path;
	@Value("${authkit.cookie.ttlRedirect:1h}")
	private Duration redirectTTL;

	@PostConstruct
	public void init() {
		if (domain == null || domain.isEmpty()) {
			try {
				domain = servletContext.getVirtualServerName();
			} catch (final UnsupportedOperationException e0) {
				try {
					domain = InetAddress.getLocalHost().getCanonicalHostName();
				} catch (final UnknownHostException e1) {
					throw new UncheckedIOException(e1);
				}
			}
		}
	}

	@Override
	public Cookie createLogonCookie(final String userSessionToken, final Duration ttl) {
		final var cookie = new Cookie(AUTH_COOKIE_NAME, userSessionToken);
		cookie.setHttpOnly(true);
		cookie.setSecure(true);
		cookie.setDomain(domain);
		cookie.setPath(path);
		cookie.setMaxAge((int) ttl.toSeconds());
		return cookie;
	}

	@Override
	public Cookie deleteLogonCookie() {
		final var cookie = new Cookie(AUTH_COOKIE_NAME, null);
		cookie.setHttpOnly(true);
		cookie.setSecure(true);
		cookie.setDomain(domain);
		cookie.setPath(path);
		return cookie;
	}

	@Override
	public String getLogonCookiePayload(final HttpServletRequest request) {
		return getCookiePayload(request, AUTH_COOKIE_NAME);
	}

	@Override
	public Cookie createRedirectAfterLoginCookie(final String redirectToPath) {
		final var cookie = new Cookie(REDIRECT_AFTER_LOGIN_COOKIE_NAME, redirectToPath);
		cookie.setHttpOnly(true);
		cookie.setSecure(true);
		cookie.setDomain(domain);
		cookie.setPath(path);
		cookie.setMaxAge((int) redirectTTL.toSeconds());
		return cookie;
	}

	@Override
	public Cookie deleteRedirectAfterLoginCookie() {
		final var cookie = new Cookie(REDIRECT_AFTER_LOGIN_COOKIE_NAME, null);
		cookie.setHttpOnly(true);
		cookie.setSecure(true);
		cookie.setDomain(domain);
		cookie.setPath(path);
		return cookie;
	}

	private String getCookiePayload(final HttpServletRequest request, final String name) {
		final var cookies = request.getCookies();
		if (cookies == null) {
			return null;
		}
		return Stream.of(cookies)
		        .filter(cookie -> name.equals(cookie.getName()))
		        .findFirst()
		        .map(Cookie::getValue)
		        .orElse(null);
	}

	@Override
	public String getRedirectAfterLoginCookiePayload(final HttpServletRequest request) {
		return getCookiePayload(request, REDIRECT_AFTER_LOGIN_COOKIE_NAME);
	}
}
