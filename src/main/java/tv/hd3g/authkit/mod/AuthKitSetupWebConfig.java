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
package tv.hd3g.authkit.mod;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import tv.hd3g.authkit.mod.component.AuthKitEndpointsListener;
import tv.hd3g.authkit.mod.service.AuditReportService;
import tv.hd3g.authkit.mod.service.AuthenticationService;
import tv.hd3g.authkit.mod.service.SecuredTokenService;

@Configuration
public class AuthKitSetupWebConfig implements WebMvcConfigurer {

	private final AuditReportService auditService;
	private final SecuredTokenService securedTokenService;
	private final AuthKitEndpointsListener authKitEndpointsListener;
	private final AuthenticationService authenticationService;

	@Autowired
	public AuthKitSetupWebConfig(final AuditReportService auditService,
	                             final SecuredTokenService securedTokenService,
	                             final AuthKitEndpointsListener authKitEndpointsListener,
	                             final AuthenticationService authenticationService) {
		this.auditService = auditService;
		this.securedTokenService = securedTokenService;
		this.authKitEndpointsListener = authKitEndpointsListener;
		this.authenticationService = authenticationService;
	}

	@Override
	public void addFormatters(final FormatterRegistry registry) {
		registry.addConverter(new StringToPasswordConvertor());
	}

	@Override
	public void addInterceptors(final InterceptorRegistry registry) {
		registry.addInterceptor(new ControllerInterceptor(
		        auditService, securedTokenService, authKitEndpointsListener, authenticationService));
	}
}
