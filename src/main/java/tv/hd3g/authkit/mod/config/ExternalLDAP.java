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
package tv.hd3g.authkit.mod.config;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Optional;

import javax.annotation.PostConstruct;
import javax.validation.constraints.NotEmpty;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import tv.hd3g.authkit.utility.CIDRUtils;

@Configuration
@ConfigurationProperties(prefix = "authkit.ldap")
public class ExternalLDAP {

	private List<LDAPEntry> servers;

	public boolean isAvailable() {
		return servers != null && servers.isEmpty() == false;
	}

	@PostConstruct
	public void init() {
		if (isAvailable()) {
			servers.forEach(LDAPEntry::init);
		}
	}

	public enum LDAPType {
		AD,
		OTHER;
	}

	public static class LDAPEntry {
		private LDAPType type;
		private String host;
		private int port;
		@NotEmpty
		private String domain;
		private String ldapTenantName;
		private String ldapCommonName;
		private String ldapMailName;
		private String organizationalUnitsAttributeName;
		private String ldapSearchLogonQuery;
		/**
		 * IPs with CIDR allowed to create internal Authkit LDAP account.
		 * Like [192.168.0.0/16, 172.16.0.0/24, 8.8.8.8/32]
		 */
		private List<CIDRUtils> allowedCreate;

		public void init() {
			if (type == null || LDAPType.OTHER.equals(type)) {
				throw new IllegalArgumentException("Not set or invalid LDAP Server type configuration: " + type);
			} else if (host == null || host.isEmpty()) {
				host = "127.0.0.1";
			} else {
				try {
					InetAddress.getByName(host);
				} catch (final UnknownHostException e) {
					throw new IllegalArgumentException("Invalid address for host configuration: " + host, e);
				}
			}
			if (port == 0) {
				port = 389;
			} else if (port < 1 || port > 65535) {
				throw new IllegalArgumentException("Invalid LDAP port in configuration: " + port);
			}
			ldapTenantName = setOptional(ldapTenantName, "sAMAccountName");
			ldapCommonName = setOptional(ldapCommonName, "cn");
			ldapMailName = setOptional(ldapMailName, "mail");
			ldapSearchLogonQuery = setOptional(ldapSearchLogonQuery,
			        "(& (sAMAccountName=<ldapTenantName>)(objectClass=user))");
			organizationalUnitsAttributeName = setOptional(organizationalUnitsAttributeName, "distinguishedName");

			if (allowedCreate == null) {
				allowedCreate = List.of();
			}
		}

		public final boolean isAllowed(final InetAddress externalAddress) {
			if (allowedCreate.isEmpty()) {
				return true;
			}
			return allowedCreate.stream().anyMatch(allowed -> allowed.isInRange(externalAddress));
		}

		private static final String setOptional(final String currentVar, final String currentDefault) {
			if (currentVar == null || currentVar.trim().isEmpty()) {
				return currentDefault;
			}
			return currentVar;
		}

		public void setType(final LDAPType type) {
			this.type = type;
		}

		public LDAPType getType() {
			return type;
		}

		public String getHost() {
			return host;
		}

		public void setHost(final String host) {
			this.host = host;
		}

		public int getPort() {
			return port;
		}

		public void setPort(final int port) {
			this.port = port;
		}

		public String getDomain() {
			return domain;
		}

		public void setDomain(final String domain) {
			this.domain = domain;
		}

		public String getLdapTenantName() {
			return ldapTenantName;
		}

		public void setLdapTenantName(final String ldapTenantName) {
			this.ldapTenantName = ldapTenantName;
		}

		public String getLdapCommonName() {
			return ldapCommonName;
		}

		public void setLdapCommonName(final String ldapCommonName) {
			this.ldapCommonName = ldapCommonName;
		}

		public String getOrganizationalUnitsAttributeName() {
			return organizationalUnitsAttributeName;
		}

		public void setOrganizationalUnitsAttributeName(final String organizationalUnitsAttributeName) {
			this.organizationalUnitsAttributeName = organizationalUnitsAttributeName;
		}

		public String getLdapSearchLogonQuery() {
			return ldapSearchLogonQuery;
		}

		public void setLdapSearchLogonQuery(final String ldapSearchLogonQuery) {
			this.ldapSearchLogonQuery = ldapSearchLogonQuery;
		}

		public String getLdapMailName() {
			return ldapMailName;
		}

		public void setLdapMailName(final String ldapMailName) {
			this.ldapMailName = ldapMailName;
		}

		public void setAllowedCreate(final List<CIDRUtils> allowedCreate) {
			this.allowedCreate = allowedCreate;
		}

		public List<CIDRUtils> getAllowedCreate() {
			return allowedCreate;
		}
	}

	public Optional<LDAPEntry> getByDomainName(final String domain) {
		if (isAvailable() == false) {
			return Optional.empty();
		}
		return getServers().stream()
		        .filter(server -> server.getDomain().equalsIgnoreCase(domain))
		        .findFirst();
	}

	public List<LDAPEntry> getServers() {
		return servers;
	}

	public void setServers(final List<LDAPEntry> servers) {
		this.servers = servers;
	}
}
