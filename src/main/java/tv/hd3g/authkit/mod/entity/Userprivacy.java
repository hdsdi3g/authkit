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
package tv.hd3g.authkit.mod.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Lob;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;

@Entity
@Table(name = "userprivacy")
public class Userprivacy extends BaseEntity {

	@NotBlank
	@Column(name = "user_uuid", length = 38)
	private String userUUID;

	@Lob
	@Column(nullable = true, columnDefinition = "blob")
	private byte[] name;

	@Lob
	@Column(nullable = true, columnDefinition = "blob")
	private byte[] address;

	@Column(length = 16)
	private String postalcode;
	/**
	 * 3char country (ISO 3166-1)
	 */
	@Column(length = 3)
	private String country;
	/**
	 * 3char lang (ISO 639-2)
	 */
	@Column(length = 3)
	private String lang;

	@Lob
	@Column(nullable = true, columnDefinition = "blob")
	private byte[] email;

	/**
	 * 128 char hash
	 */
	@Column(name = "hashed_email", length = 128)
	private String hashedEmail;
	@Column(length = 128)
	private String company;

	@Lob
	@Column(nullable = true, columnDefinition = "blob")
	private byte[] phone;

	/**
	 * NEVER USE DIRECTLY, ONLY SET FOR HIBERNATE
	 */
	public Userprivacy() {
	}

	public Userprivacy(final String userUUID) {
		initCreate();
		this.userUUID = userUUID;
	}

	public byte[] getName() {
		return name;
	}

	public void setName(final byte[] name) {
		this.name = name;
	}

	public byte[] getAddress() {
		return address;
	}

	public void setAddress(final byte[] address) {
		this.address = address;
	}

	public String getPostalcode() {
		return postalcode;
	}

	public void setPostalcode(final String postalcode) {
		this.postalcode = postalcode;
	}

	public String getCountry() {
		return country;
	}

	public void setCountry(final String country) {
		this.country = country;
	}

	public String getLang() {
		return lang;
	}

	public void setLang(final String lang) {
		this.lang = lang;
	}

	public byte[] getEmail() {
		return email;
	}

	public void setEmail(final byte[] email) {
		this.email = email;
	}

	public String getHashedEmail() {
		return hashedEmail;
	}

	public void setHashedEmail(final String hashedEmail) {
		this.hashedEmail = hashedEmail;
	}

	public String getCompany() {
		return company;
	}

	public void setCompany(final String company) {
		this.company = company;
	}

	public byte[] getPhone() {
		return phone;
	}

	public void setPhone(final byte[] phone) {
		this.phone = phone;
	}

	public String getUserUUID() {
		return userUUID;
	}

}