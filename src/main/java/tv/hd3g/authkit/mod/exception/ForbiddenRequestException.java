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
package tv.hd3g.authkit.mod.exception;

import static org.springframework.http.HttpStatus.FORBIDDEN;

import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import tv.hd3g.authkit.mod.service.AuditReportService;

public class ForbiddenRequestException extends SecurityRejectedRequestException {

	public ForbiddenRequestException(final String logMessage, final String userUUID) {
		super(logMessage, FORBIDDEN, UUID.fromString(userUUID));
	}

	@Override
	public void pushAudit(final AuditReportService auditService, final HttpServletRequest request) {
		auditService.interceptForbiddenRequest(request);
	}
}
