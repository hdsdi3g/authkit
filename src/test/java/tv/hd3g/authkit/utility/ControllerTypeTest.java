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
package tv.hd3g.authkit.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static tv.hd3g.authkit.utility.ControllerType.CLASSIC;
import static tv.hd3g.authkit.utility.ControllerType.REST;

import org.junit.jupiter.api.Test;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RestController;

class ControllerTypeTest {

	@Test
	void testGetFromClass() {
		assertEquals(CLASSIC, ControllerType.getFromClass(CtrlClassic.class));
		assertEquals(REST, ControllerType.getFromClass(CtrlRest.class));
		assertEquals(REST, ControllerType.getFromClass(HybridCtrl.class));
		assertThrows(IllegalArgumentException.class, () -> ControllerType.getFromClass(NotACtrl.class));
	}

	private static class NotACtrl {

	}

	@RestController
	private static class CtrlRest {

	}

	@Controller
	private static class CtrlClassic {

	}

	@RestController
	@Controller
	private static class HybridCtrl {

	}

}
