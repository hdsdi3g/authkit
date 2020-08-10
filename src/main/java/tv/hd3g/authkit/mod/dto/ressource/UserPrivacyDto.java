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

import java.util.Date;
import java.util.Objects;
import java.util.function.Function;

import javax.validation.constraints.Size;

import org.springframework.hateoas.RepresentationModel;
import org.springframework.lang.Nullable;

import tv.hd3g.authkit.mod.dto.ExternalAuthUserDto;
import tv.hd3g.authkit.mod.entity.Userprivacy;

/**
 * In and Out DTO
 */
public class UserPrivacyDto extends RepresentationModel<UserPrivacyDto> {

	/**
	 * Ignored during creation/update
	 */
	@Nullable
	private Date created;
	/**
	 * Ignored during creation/update
	 */
	@Nullable
	private String userUUID;
	@Nullable
	private String name;
	@Nullable
	private String address;
	@Nullable
	@Size(max = 16)
	private String postalcode;
	@Nullable
	@Size(max = 3)
	private String country;
	@Nullable
	@Size(max = 3)
	private String lang;
	@Nullable
	private String email;
	@Nullable
	@Size(max = 128)
	private String company;
	@Nullable
	private String phone;

	public UserPrivacyDto() {
	}

	public UserPrivacyDto(final Userprivacy user, final Function<byte[], String> unCipher) {
		created = user.getCreated();
		userUUID = user.getUserUUID();
		name = unCipher.apply(user.getName());
		address = unCipher.apply(user.getAddress());
		postalcode = user.getPostalcode();
		country = user.getCountry();
		lang = user.getLang();
		email = unCipher.apply(user.getEmail());
		company = user.getCompany();
		phone = unCipher.apply(user.getPhone());
	}

	public UserPrivacyDto(final ExternalAuthUserDto importFromLDAP) {
		if (importFromLDAP.getUserLongName() != null) {
			name = importFromLDAP.getUserLongName();
		}
		if (importFromLDAP.getUserEmail() != null) {
			email = importFromLDAP.getUserEmail();
		}
		/**
		 * ... more from LDAP
		 */
	}

	public void mergue(final Userprivacy user, final Function<String, byte[]> cipher) {
		if (name != null) {
			user.setName(cipher.apply(name));
		}
		if (address != null) {
			user.setAddress(cipher.apply(address));
		}
		if (postalcode != null) {
			user.setPostalcode(postalcode);
		}
		if (country != null) {
			user.setCountry(country);
		}
		if (lang != null) {
			user.setLang(lang);
		}
		if (email != null) {
			user.setEmail(cipher.apply(email));
		}
		if (company != null) {
			user.setCompany(company);
		}
		if (phone != null) {
			user.setPhone(cipher.apply(phone));
		}
	}

	@Override
	public int hashCode() {
		final var prime = 31;
		var result = super.hashCode();
		result = prime * result + Objects.hash(address, company, country, created, email, lang, name,
		        phone, postalcode, userUUID);
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
		final var other = (UserPrivacyDto) obj;
		return Objects.equals(address, other.address) && Objects.equals(company, other.company) && Objects.equals(
		        country, other.country) && Objects.equals(created, other.created) && Objects.equals(email, other.email)
		       && Objects.equals(lang, other.lang) && Objects.equals(
		               name, other.name) && Objects.equals(phone, other.phone) && Objects.equals(postalcode,
		                       other.postalcode) && Objects.equals(userUUID, other.userUUID);
	}

	public Date getCreated() {
		return created;
	}

	public String getUserUUID() {
		return userUUID;
	}

	public String getName() {
		return name;
	}

	public String getAddress() {
		return address;
	}

	public String getPostalcode() {
		return postalcode;
	}

	public String getCountry() {
		return country;
	}

	public String getLang() {
		return lang;
	}

	public String getEmail() {
		return email;
	}

	public String getCompany() {
		return company;
	}

	public String getPhone() {
		return phone;
	}

	public void setName(final String name) {
		this.name = name;
	}

	public void setAddress(final String address) {
		this.address = address;
	}

	public void setPostalcode(final String postalcode) {
		this.postalcode = postalcode;
	}

	public void setCountry(final String country) {
		this.country = country;
	}

	public void setLang(final String lang) {
		this.lang = lang;
	}

	public void setEmail(final String email) {
		this.email = email;
	}

	public void setCompany(final String company) {
		this.company = company;
	}

	public void setPhone(final String phone) {
		this.phone = phone;
	}

}
