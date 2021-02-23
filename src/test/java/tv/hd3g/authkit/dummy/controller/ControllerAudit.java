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
package tv.hd3g.authkit.dummy.controller;

import org.springframework.stereotype.Controller;

import tv.hd3g.commons.authkit.AuditAfter;

@Controller
@AuditAfter("OnClass")
public class ControllerAudit {

	@AuditAfter(value = "useSecurity", useSecurity = true)
	public void verbUseSecurity() {
	}

	@AuditAfter(value = "changeSecurity", changeSecurity = true)
	public void verbChangeSecurity() {
	}

	@AuditAfter(value = "cantDoErrors", cantDoErrors = true)
	public void verbCantDoErrors() {
	}

	@AuditAfter(value = "All", useSecurity = true, changeSecurity = true, cantDoErrors = true)
	public void verbAll() {
	}

	@AuditAfter("simple")
	public void verbSimple() {
	}

	@AuditAfter("combinated1")
	@AuditAfter("combinated2")
	public void verbCombinated() {
	}

}
