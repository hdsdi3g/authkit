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

import java.util.Optional;

import tv.hd3g.authkit.mod.dto.Password;
import tv.hd3g.authkit.mod.entity.Credential;
import tv.hd3g.authkit.mod.service.AuditReportService.RejectLoginCause;

public interface CheckPasswordService {

	Optional<RejectLoginCause> checkPassword(Password userEnterPassword, Credential credential);

}
