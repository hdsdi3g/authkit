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
package tv.hd3g.authkit.mod.service;

import static javax.naming.directory.SearchControls.SUBTREE_SCOPE;
import static javax.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Optional;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import tv.hd3g.authkit.mod.ExternalLDAP;
import tv.hd3g.authkit.mod.ExternalLDAP.LDAPEntry;
import tv.hd3g.authkit.mod.ExternalLDAP.LDAPType;
import tv.hd3g.authkit.mod.dto.ExternalAuthUserDto;
import tv.hd3g.authkit.mod.dto.Password;
import tv.hd3g.authkit.mod.exception.AuthKitException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.BadPasswordUserCantLoginException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.ExternalAuthErrorCantLoginException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.NoPasswordUserCantLoginException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.UnknownUserCantLoginException;

@Service
public class ExternalAuthClientLDAPServiceImpl implements ExternalAuthClientService {
	private static Logger log = LogManager.getLogger();

	@Autowired
	private ExternalLDAP externalLDAP;

	@Override
	public boolean isAvailable() {
		return externalLDAP != null && externalLDAP.isAvailable();
	}

	private LDAPEntry getConfiguration(final String domain) {
		final var oLDAPEntry = externalLDAP.getByDomainName(domain);
		if (oLDAPEntry.isEmpty()) {
			log.error("Can't found configuration for {} domain", domain);
			throw new AuthKitException(SC_INTERNAL_SERVER_ERROR, "Can't login");
		}
		return oLDAPEntry.get();
	}

	@Override
	public ExternalAuthUserDto logonUser(final String login,
	                                     final Password password,
	                                     final String domain) throws UserCantLoginException {
		if (isAvailable() == false) {
			throw new ExternalAuthErrorCantLoginException();
		} else if (password == null || password.length() == 0) {
			throw new NoPasswordUserCantLoginException();
		}
		final var configuration = getConfiguration(domain);
		if (configuration.getType() != LDAPType.AD) {
			throw new IllegalArgumentException("Unsuported LDAP typ server: " + configuration.getType());
		}

		final Hashtable<String, String> props = new Hashtable<>();
		props.put(Context.SECURITY_PRINCIPAL, login + "@" + domain);
		props.put(Context.SECURITY_CREDENTIALS, password.subSequence(0, password.length()).toString());
		props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		props.put(Context.PROVIDER_URL, "ldap://" + configuration.getHost() + ":" + configuration.getPort() + "/");
		props.put("java.naming.ldap.attributes.binary", "tokenGroups");

		try {
			final LdapContext context = new InitialLdapContext(props, null);
			if (((String) context.getEnvironment().get(Context.SECURITY_PRINCIPAL)).contains("@") == false) {
				throw new UnknownUserCantLoginException();
			}

			final SearchControls controls = new SearchControls();
			controls.setSearchScope(SUBTREE_SCOPE);
			controls.setCountLimit(1);
			controls.setTimeLimit(500);

			final var answer = context.search(
			        toDC(domain),
			        configuration.getLdapSearchLogonQuery().replace("<ldapTenantName>", login),
			        controls);
			if (answer.hasMore() == false) {
				log.error("Can't get LDAP entry for {}", login);
				throw new UnknownUserCantLoginException();
			}
			final Attributes attr = answer.next().getAttributes();

			final Attribute user = attr.get(configuration.getLdapTenantName());
			if (user == null) {
				log.error("Can't get LDAP user for {}", login);
				throw new UnknownUserCantLoginException();
			}

			final var userLongName = extractLDAPSearchResultVar(configuration.getLdapCommonName(), attr)
			        .orElseThrow(() -> new NamingException("Can't get LDAP user CN for " + login));
			final var userEmail = extractLDAPSearchResultVar(configuration.getLdapMailName(), attr).orElse(null);
			final var memberOf = extractLDAPSearchResultVars("memberOf", attr)
			        .map(extractOrganizationalUnits)
			        .collect(Collectors.toUnmodifiableList());

			return new ExternalAuthUserDto(login,
			        domain,
			        userLongName,
			        userEmail,
			        memberOf);
		} catch (final CommunicationException e) {
			log.error("Failed to connect to {}: {}", configuration.getHost(), configuration.getPort(), e);
			throw new ExternalAuthErrorCantLoginException();
		} catch (final NamingException e) {
			log.error("Failed to authenticate {}@{} through {}", login, domain, configuration.getHost(), e);
			throw new BadPasswordUserCantLoginException();
		}
	}

	private Optional<String> extractLDAPSearchResultVar(final String key,
	                                                    final Attributes attr) {
		final var item = attr.get(key);
		if (item == null) {
			return Optional.empty();
		}
		try {
			final var value = item.get();
			if (value instanceof String == false) {
				return Optional.ofNullable(String.valueOf(value));
			} else {
				return Optional.ofNullable((String) value);
			}
		} catch (final NamingException e) {
			log.debug("Can't found {} in LDAP datas", key, e);
		}
		return Optional.empty();
	}

	private Stream<String> extractLDAPSearchResultVars(final String key,
	                                                   final Attributes attr) {
		final var item = attr.get(key);
		if (item == null) {
			return Stream.empty();
		}
		try {
			final var size = item.size();
			return StreamSupport.stream(Spliterators.spliterator(item.getAll().asIterator(), size, Spliterator.ORDERED),
			        false).map(value -> {
				        if (value instanceof String == false) {
					        return String.valueOf(value);
				        } else {
					        return (String) value;
				        }
			        });
		} catch (final NamingException e) {
			log.debug("Can't found {} in LDAP datas", key, e);
		}
		return Stream.empty();
	}

	private static final UnaryOperator<String> extractOrganizationalUnits = ldapEntry -> {
		/**
		 * From CN=AuthKit Security Group,OU=authkit,DC=home,DC=hd3g,DC=tv
		 * to AuthKit Security Group (home.hd3g.tv/authkit)
		 */
		final var entrySplited = ldapEntry.split(",");
		final var commonName = Arrays.stream(entrySplited)
		        .filter(dn -> dn.toUpperCase().startsWith("CN="))
		        .map(dn -> dn.substring(3)).collect(Collectors.joining());
		final var organizationalUnits = Arrays.stream(entrySplited)
		        .filter(dn -> dn.toUpperCase().startsWith("OU="))
		        .map(dn -> dn.substring(3)).collect(Collectors.joining("/", "/", ""));
		final var domain = Arrays.stream(entrySplited)
		        .filter(dn -> dn.toUpperCase().startsWith("DC="))
		        .map(dn -> dn.substring(3)).collect(Collectors.joining("."));
		return commonName + " (" + domain + organizationalUnits + ")";
	};

	private static String toDC(final String domain) {
		return Arrays.stream(domain.split("\\."))
		        .filter(entry -> entry.isEmpty() == false)
		        .collect(Collectors.joining(",DC=", "DC=", ""));
	}

	@Override
	public Optional<String> getDefaultDomainName() {
		if (isAvailable() == false) {
			return Optional.empty();
		}
		return Optional.ofNullable(externalLDAP.getServers().get(0).getDomain());
	}

	@Override
	public boolean isIPAllowedToCreateUserAccount(final InetAddress address, final String domain) {
		if (isAvailable() == false) {
			return false;
		}
		return externalLDAP.getByDomainName(domain).map(entry -> entry.isAllowed(address)).orElse(false);
	}
}
