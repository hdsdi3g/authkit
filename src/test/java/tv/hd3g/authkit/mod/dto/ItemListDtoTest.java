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
package tv.hd3g.authkit.mod.dto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import tv.hd3g.authkit.mod.dto.ressource.ItemListDto;
import tv.hd3g.authkit.mod.dto.ressource.UserDto;
import tv.hd3g.authkit.tool.HashCodeEqualsTest;

class ItemListDtoTest extends HashCodeEqualsTest {

	@Mock
	private List<UserDto> list;

	@BeforeEach
	public void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
	}

	@Test
	void testGetItems() {
		final var i = new ItemListDto<>(list);
		assertEquals(list, i.getItems());
	}

	@Override
	protected Object[] makeSameInstances() {
		return new Object[] { new ItemListDto<>(list), new ItemListDto<>(list) };
	}

}
