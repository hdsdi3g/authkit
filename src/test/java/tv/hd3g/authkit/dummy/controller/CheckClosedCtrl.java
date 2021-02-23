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

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;

import tv.hd3g.commons.authkit.AuditAfter;
import tv.hd3g.commons.authkit.CheckBefore;
import tv.hd3g.commons.authkit.RenforceCheckBefore;

@Controller
@CheckBefore("secureOnClass")
@AuditAfter("OnClass")
public class CheckClosedCtrl {

	@CheckBefore("secureOnMethodOr1")
	@CheckBefore("secureOnMethodOr2")
	@AuditAfter("combinated1")
	@AuditAfter("combinated2")
	@RenforceCheckBefore
	@GetMapping("CheckClosedCtrl/0")
	public void verb() {
	}

	@GetMapping("CheckClosedCtrl/1")
	public void verbGET() {
	}

	@PostMapping("CheckClosedCtrl/2")
	public void verbPOST() {
	}

	@PutMapping("CheckClosedCtrl/3")
	public void verbPUT() {
	}

	@DeleteMapping("CheckClosedCtrl/4")
	public void verbDELETE() {
	}

	@PatchMapping("CheckClosedCtrl/5")
	public void verbPATCH() {
	}

}
