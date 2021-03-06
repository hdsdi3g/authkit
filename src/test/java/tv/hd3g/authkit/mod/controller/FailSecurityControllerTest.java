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
package tv.hd3g.authkit.mod.controller;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static tv.hd3g.authkit.mod.service.CookieService.AUTH_COOKIE_NAME;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;

@SpringBootTest
@AutoConfigureMockMvc
class FailSecurityControllerTest {

	private final ResultMatcher statusUnauthorized = status().isUnauthorized();
	private final ResultMatcher contentTypeHtmlUtf8 = content().contentType(new MediaType("text", "html", UTF_8));
	private final ResultMatcher modelHasNoErrors = model().hasNoErrors();
	private final ResultMatcher modelHasNoSessionAttr = model().attributeDoesNotExist("jwtsession");
	private final ResultMatcher notAuthCookie = cookie().doesNotExist(AUTH_COOKIE_NAME);

	@Autowired
	private MockMvc mvc;

	@Test
	void unauthorized_nonREST() throws Exception {
		mvc.perform(get("/test/ControllerWithSecure/verbWithSecure")
		        .accept(TEXT_HTML))
		        .andExpect(statusUnauthorized)
		        .andExpect(contentTypeHtmlUtf8)
		        .andExpect(modelHasNoErrors)
		        .andExpect(modelHasNoSessionAttr)
		        .andExpect(notAuthCookie);
	}

	@Test
	void unauthorized_REST() throws Exception {
		mvc.perform(get("/test/RESTControllerWithoutSecure/verbWithSecure")
		        .accept(APPLICATION_JSON))
		        .andExpect(statusUnauthorized)
		        .andExpect(notAuthCookie);
	}

}
