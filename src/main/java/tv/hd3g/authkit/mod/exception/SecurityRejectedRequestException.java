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

import java.io.IOException;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;

import tv.hd3g.authkit.mod.service.AuditReportService;

public abstract class SecurityRejectedRequestException extends RuntimeException {

	private final HttpStatus status;
	private final UUID userUUID;

	protected SecurityRejectedRequestException(final String logMessage,
	                                           final HttpStatus status,
	                                           final UUID userUUID) {
		super(logMessage);
		this.status = status;
		this.userUUID = userUUID;
	}

	protected SecurityRejectedRequestException(final String logMessage,
	                                           final HttpStatus status) {
		this(logMessage, status, null);
	}

	public abstract void pushAudit(final AuditReportService auditService, HttpServletRequest request);

	/**
	 * For Sonar needs (squid:S1948)
	 */
	private void writeObject(final java.io.ObjectOutputStream out) throws IOException {
	}

	/**
	 * For Sonar needs (squid:S1948)
	 */
	private void readObject(final java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
	}

	public HttpStatus getStatusCode() {
		return status;
	}

	public UUID getUserUUID() {
		return userUUID;
	}
}
