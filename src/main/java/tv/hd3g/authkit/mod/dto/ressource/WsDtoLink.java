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
package tv.hd3g.authkit.mod.dto.ressource;

import java.util.Objects;

import org.springframework.hateoas.Link;
import org.springframework.web.bind.annotation.RequestMethod;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * See https://stackoverflow.com/questions/49615358/spring-hateoas-controllerlinkbuilder-adds-null-fields
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class WsDtoLink extends Link {

	private final String action;

	public WsDtoLink(final Link link, final RequestMethod method) {
		super(link.getTemplate(), link.getRel());
		action = method.name();
	}

	public String getAction() {
		return action;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Objects.hash(action);
		return result;
	}

	@Override
	public boolean equals(final Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final WsDtoLink other = (WsDtoLink) obj;
		return Objects.equals(action, other.action);
	}
}
