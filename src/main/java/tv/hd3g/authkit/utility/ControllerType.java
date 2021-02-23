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

import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RestController;

public enum ControllerType {
	CLASSIC,
	REST;

	public static ControllerType getFromClass(final Class<?> referer) {
		if (referer.getAnnotationsByType(RestController.class).length > 0) {
			return ControllerType.REST;
		} else if (referer.getAnnotationsByType(Controller.class).length > 0) {
			return ControllerType.CLASSIC;
		} else {
			final var annotations = Stream.of(referer.getAnnotations())
			        .map(a -> "@" + a.annotationType().getSimpleName())
			        .collect(Collectors.joining(", "));
			throw new IllegalArgumentException("Can't extract the controller type from: "
			                                   + referer.getName() + " {" + annotations + "}");
		}
	}
}