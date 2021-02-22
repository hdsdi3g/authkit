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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import tv.hd3g.authkit.mod.dto.validated.ListStringDto;

class ListStringDtoTest {

	private ListStringDto listStringDto;
	@Mock
	private List<String> list;

	@BeforeEach
	public void init() throws Exception {
		MockitoAnnotations.openMocks(this).close();
		listStringDto = new ListStringDto();
		listStringDto.setList(list);
	}

	@Test
	void testGetList() {
		assertNotNull(listStringDto.getList());
		assertTrue(listStringDto.getList().isEmpty());
	}

	@Test
	void testSetList() {
		final var list = new ArrayList<String>();
		listStringDto.setList(list);
		assertEquals(list, listStringDto.getList());
	}
}
