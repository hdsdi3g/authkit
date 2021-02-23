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
package tv.hd3g.authkit.dummy.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import tv.hd3g.commons.authkit.AuditAfter;
import tv.hd3g.commons.authkit.CheckBefore;
import tv.hd3g.commons.authkit.RenforceCheckBefore;

@RestController
public class CheckOpenCtrl {

	@GetMapping("CheckOpenCtrl/0")
	public ResponseEntity<Void> verb() {
		return null;
	}

	@CheckBefore("secureOnMethodOr1")
	@CheckBefore("secureOnMethodOr2")
	@AuditAfter("combinated1")
	@AuditAfter("combinated2")
	@RenforceCheckBefore
	@GetMapping("CheckOpenCtrl/1")
	public ResponseEntity<Void> verbOther() {
		return null;
	}
}
