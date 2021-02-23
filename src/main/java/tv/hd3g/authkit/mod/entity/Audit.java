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
package tv.hd3g.authkit.mod.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

@Entity
@Table(name = "audit")
public class Audit extends BaseEntity {

	@NotEmpty
	@Column(length = 60)
	private String appname;

	@NotEmpty
	@Column(length = 38)
	private String eventref;

	@NotNull
	@Column(length = 128)
	private String clientsourcehost;

	@NotNull
	private Integer clientsourceport;

	@NotEmpty
	private String eventname;

	@NotEmpty
	@Column(length = 10)
	private String requestprotocol;

	@NotEmpty
	@Column(length = 10)
	private String requestmethod;

	@NotNull
	@Column(length = 128)
	private String requestserverhost;

	@NotNull
	private Integer requestserverport;

	@NotEmpty
	@Column(length = 255)
	private String requestpath;

	@NotEmpty
	@Column(length = 255)
	private String requestcontenttype;

	@NotNull
	private Long requestlength;

	@Column(length = 1024)
	private String context;

	@Column(length = 255)
	private String triggeredexception;

	@Column(length = 38)
	private String useruuid;

	/**
	 * NEVER USE DIRECTLY, ONLY SET FOR HIBERNATE
	 */
	public Audit() {
	}

	/**
	 * Protect entry size
	 */
	private static String pSize(final String entry, final int maxSize) {
		if (entry == null) {
			return null;
		} else if (entry.length() <= maxSize) {
			return entry;
		}
		return entry.substring(0, maxSize);
	}

	public Audit(final String appname,
	             final String eventref,
	             final String clientsourcehost,
	             final Integer clientsourceport,
	             final String requestserverhost,
	             final Integer requestserverport,
	             final String eventname,
	             final String requestprotocol,
	             final String requestmethod,
	             final String requestpath,
	             final String requestcontenttype,
	             final long requestlength) {
		initCreate();
		this.appname = pSize(appname, 60);
		this.eventref = pSize(eventref, 38);
		this.clientsourcehost = clientsourcehost;
		this.clientsourceport = clientsourceport;
		this.requestserverhost = requestserverhost;
		this.requestserverport = requestserverport;
		this.eventname = pSize(eventname, 60);
		this.requestprotocol = pSize(requestprotocol, 10);
		this.requestmethod = pSize(requestmethod, 10);
		this.requestpath = pSize(requestpath, 255);
		this.requestcontenttype = pSize(requestcontenttype, 255);
		this.requestlength = requestlength;
	}

	public String getAppname() {
		return appname;
	}

	public String getEventref() {
		return eventref;
	}

	public String getClientsourcehost() {
		return clientsourcehost;
	}

	public Integer getClientsourceport() {
		return clientsourceport;
	}

	public String getRequestserverhost() {
		return requestserverhost;
	}

	public Integer getRequestserverport() {
		return requestserverport;
	}

	public String getEventname() {
		return eventname;
	}

	public String getRequestprotocol() {
		return requestprotocol;
	}

	public String getRequestmethod() {
		return requestmethod;
	}

	public String getRequestpath() {
		return requestpath;
	}

	public String getContext() {
		return context;
	}

	public void setContext(final String context) {
		this.context = pSize(context, 1024);
	}

	public String getTriggeredexception() {
		return triggeredexception;
	}

	public void setTriggeredexception(final String triggeredexception) {
		this.triggeredexception = pSize(triggeredexception, 255);
	}

	public String getUseruuid() {
		return useruuid;
	}

	public void setUseruuid(final String useruuid) {
		this.useruuid = pSize(useruuid, 38);
	}
}
