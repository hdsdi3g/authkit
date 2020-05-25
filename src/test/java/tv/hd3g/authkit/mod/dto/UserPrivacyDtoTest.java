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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomString;
import static tv.hd3g.authkit.tool.DataGenerator.makeRandomThings;
import static tv.hd3g.authkit.tool.DataGenerator.makeUUID;
import static tv.hd3g.authkit.tool.DataGenerator.makeUserLogin;

import java.util.Date;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import tv.hd3g.authkit.mod.dto.ressource.UserPrivacyDto;
import tv.hd3g.authkit.mod.entity.Userprivacy;
import tv.hd3g.authkit.tool.HashCodeEqualsTest;

class UserPrivacyDtoTest extends HashCodeEqualsTest {

	private static final Function<String, byte[]> cipher = v -> v.getBytes(UTF_8);
	private static final Function<byte[], String> unCipher = b -> new String(b, UTF_8);

	private UserPrivacyDto userPrivacyDto;
	private Userprivacy userPrivacy;
	private ExternalAuthUserDto ldapUserDto;

	private Date created;
	private String userUUID;
	private String name;
	private String address;
	private String postalcode;
	private String country;
	private String lang;
	private String email;
	private String company;
	private String phone;

	@BeforeEach
	void init() {
		userUUID = makeUUID();
		name = makeRandomString();
		address = makeRandomString();
		postalcode = makeUserLogin();
		country = makeRandomString();
		lang = makeRandomString();
		email = makeRandomString();
		company = makeRandomString();
		phone = makeRandomString();

		userPrivacy = new Userprivacy(userUUID);
		userPrivacy.setName(name.getBytes(UTF_8));
		userPrivacy.setAddress(address.getBytes(UTF_8));
		userPrivacy.setPostalcode(postalcode);
		userPrivacy.setCountry(country);
		userPrivacy.setLang(lang);
		userPrivacy.setEmail(email.getBytes(UTF_8));
		userPrivacy.setCompany(company);
		userPrivacy.setPhone(phone.getBytes(UTF_8));

		created = userPrivacy.getCreated();

		userPrivacyDto = new UserPrivacyDto(userPrivacy, unCipher);
		ldapUserDto = new ExternalAuthUserDto(makeUserLogin(), makeUserLogin(), makeRandomString(), makeRandomString(),
		        makeRandomThings().collect(Collectors.toUnmodifiableList()));
	}

	@Test
	void testGetCreated() {
		assertEquals(created, userPrivacyDto.getCreated());
	}

	@Test
	void testGetUserUUID() {
		assertEquals(userUUID, userPrivacyDto.getUserUUID());
	}

	@Test
	void testGetName() {
		assertEquals(name, userPrivacyDto.getName());
	}

	@Test
	void testGetName_LDAP() {
		userPrivacyDto = new UserPrivacyDto(ldapUserDto);
		assertEquals(ldapUserDto.getUserLongName(), userPrivacyDto.getName());
	}

	@Test
	void testGetAddress() {
		assertEquals(address, userPrivacyDto.getAddress());
	}

	@Test
	void testGetPostalcode() {
		assertEquals(postalcode, userPrivacyDto.getPostalcode());
	}

	@Test
	void testGetCountry() {
		assertEquals(country, userPrivacyDto.getCountry());
	}

	@Test
	void testGetLang() {
		assertEquals(lang, userPrivacyDto.getLang());
	}

	@Test
	void testGetEmail_LDAP() {
		userPrivacyDto = new UserPrivacyDto(ldapUserDto);
		assertEquals(ldapUserDto.getUserEmail(), userPrivacyDto.getEmail());
	}

	@Test
	void testGetEmail() {
		assertEquals(email, userPrivacyDto.getEmail());
	}

	@Test
	void testGetCompany() {
		assertEquals(company, userPrivacyDto.getCompany());
	}

	@Test
	void testGetPhone() {
		assertEquals(phone, userPrivacyDto.getPhone());
	}

	@Test
	void testSetName() {
		final var name = makeRandomString();
		userPrivacyDto.setName(name);
		assertEquals(name, userPrivacyDto.getName());

		final var user = new Userprivacy();
		userPrivacyDto.mergue(user, cipher);
		assertEquals(name, unCipher.apply(user.getName()));
	}

	@Test
	void testSetAddress() {
		final var address = makeRandomString();
		userPrivacyDto.setAddress(address);
		assertEquals(address, userPrivacyDto.getAddress());

		final var user = new Userprivacy();
		userPrivacyDto.mergue(user, cipher);
		assertEquals(address, unCipher.apply(user.getAddress()));
	}

	@Test
	void testSetPostalcode() {
		final var postalcode = makeRandomString();
		userPrivacyDto.setPostalcode(postalcode);
		assertEquals(postalcode, userPrivacyDto.getPostalcode());

		final var user = new Userprivacy();
		userPrivacyDto.mergue(user, cipher);
		assertEquals(postalcode, user.getPostalcode());
	}

	@Test
	void testSetCountry() {
		final var country = makeRandomString();
		userPrivacyDto.setCountry(country);
		assertEquals(country, userPrivacyDto.getCountry());

		final var user = new Userprivacy();
		userPrivacyDto.mergue(user, cipher);
		assertEquals(country, user.getCountry());
	}

	@Test
	void testSetLang() {
		final var lang = makeRandomString();
		userPrivacyDto.setLang(lang);
		assertEquals(lang, userPrivacyDto.getLang());

		final var user = new Userprivacy();
		userPrivacyDto.mergue(user, cipher);
		assertEquals(lang, user.getLang());
	}

	@Test
	void testSetEmail() {
		final var email = makeRandomString();
		userPrivacyDto.setEmail(email);
		assertEquals(email, userPrivacyDto.getEmail());

		final var user = new Userprivacy();
		userPrivacyDto.mergue(user, cipher);
		assertEquals(email, unCipher.apply(user.getEmail()));
	}

	@Test
	void testSetCompany() {
		final var company = makeRandomString();
		userPrivacyDto.setCompany(company);
		assertEquals(company, userPrivacyDto.getCompany());

		final var user = new Userprivacy();
		userPrivacyDto.mergue(user, cipher);
		assertEquals(company, user.getCompany());
	}

	@Test
	void testSetPhone() {
		final var phone = makeRandomString();
		userPrivacyDto.setPhone(phone);
		assertEquals(phone, userPrivacyDto.getPhone());

		final var user = new Userprivacy();
		userPrivacyDto.mergue(user, cipher);
		assertEquals(phone, unCipher.apply(user.getPhone()));
	}

	@Override
	protected Object[] makeSameInstances() {
		return new Object[] {
		                      new UserPrivacyDto(userPrivacy, unCipher),
		                      new UserPrivacyDto(userPrivacy, unCipher)
		};
	}

}
