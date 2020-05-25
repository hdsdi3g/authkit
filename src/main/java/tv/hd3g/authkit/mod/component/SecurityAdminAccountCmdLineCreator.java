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
package tv.hd3g.authkit.mod.component;

import java.util.Optional;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import tv.hd3g.authkit.mod.dto.Password;
import tv.hd3g.authkit.mod.service.CmdLineService;

/**
 * Usage:
 * $ export AUTHKIT_NEWADMIN=&lt;security admin login name&gt;
 * $ export AUTHKIT_PASSWORD=&lt;security admin password&gt;
 * $ java -jar myspringapp.jar create-security-admin
 */
@Component
public class SecurityAdminAccountCmdLineCreator implements ApplicationRunner {

	public static final String AUTHKIT_NEWADMIN_ENVKEY = "AUTHKIT_NEWADMIN";
	public static final String AUTHKIT_PASSWORD_ENVKEY = "AUTHKIT_PASSWORD";

	@Autowired
	private CmdLineService cmdLineService;

	@Override
	@Transactional
	public void run(final ApplicationArguments args) throws Exception {
		if (args.getNonOptionArgs().contains("create-security-admin") == false) {
			return;
		}

		final var newadmin = Optional.ofNullable(System.getenv(AUTHKIT_NEWADMIN_ENVKEY))
		        .or(() -> Optional.ofNullable(System.getProperty(AUTHKIT_NEWADMIN_ENVKEY)))
		        .orElseThrow(
		                () -> new IllegalArgumentException(
		                        "You must set a \"" + AUTHKIT_NEWADMIN_ENVKEY + "\" as environment var"));
		final var password = Optional.ofNullable(System.getenv(AUTHKIT_PASSWORD_ENVKEY))
		        .or(() -> Optional.ofNullable(System.getProperty(AUTHKIT_PASSWORD_ENVKEY)))
		        .orElseThrow(
		                () -> new IllegalArgumentException(
		                        "You must set a \"" + AUTHKIT_PASSWORD_ENVKEY + "\" as environment var"));

		cmdLineService.addOrUpdateSecurityAdminUser(newadmin, new Password(password));

		if (args.getNonOptionArgs().contains("dont-quit-after-done") == false) {
			System.exit(0);
		}
	}

}
