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

import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toUnmodifiableList;
import static java.util.stream.Collectors.toUnmodifiableMap;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import tv.hd3g.commons.authkit.AuditAfter;
import tv.hd3g.commons.authkit.AuditAllAfter;
import tv.hd3g.commons.authkit.CheckBefore;
import tv.hd3g.commons.authkit.CheckOneBefore;
import tv.hd3g.commons.authkit.RenforceCheckBefore;

public class AnnotatedControllerClass {

	private final List<CheckBefore> allClassCheckBefore;
	private final Map<Method, List<CheckBefore>> allMethodsCheckBefore;
	private final Map<Method, List<AuditAfter>> auditAfterListByMethods;
	private final Map<Method, List<CheckBefore>> checkBeforeListByMethods;
	private final boolean allClassRenforceCheckBefore;
	private final Map<Method, Boolean> allMethodsRenforceCheckBefore;
	private final Map<Method, Boolean> allMethodsRequireValidAuth;
	private final ControllerType controllerType;

	public AnnotatedControllerClass(final Class<?> referer) {
		final Function<CheckOneBefore, Stream<CheckBefore>> extractCheckOnBefore = audits -> stream(audits.value());
		final Function<AuditAllAfter, Stream<AuditAfter>> extractAuditAllAfter = audits -> stream(audits.value());

		final var refererMethods = stream(referer.getMethods()).collect(toUnmodifiableList());

		allClassCheckBefore = Stream.concat(
		        stream(referer.getAnnotationsByType(CheckBefore.class)),
		        stream(referer.getAnnotationsByType(CheckOneBefore.class))
		                .flatMap(extractCheckOnBefore))
		        .distinct()
		        .collect(toUnmodifiableList());

		final var allClassAuditsAfter = Stream.concat(
		        stream(referer.getAnnotationsByType(AuditAfter.class)),
		        stream(referer.getAnnotationsByType(AuditAllAfter.class))
		                .flatMap(extractAuditAllAfter))
		        .distinct()
		        .collect(toUnmodifiableList());

		allClassRenforceCheckBefore = referer.getAnnotationsByType(RenforceCheckBefore.class).length > 0;

		allMethodsCheckBefore = refererMethods.stream()
		        .collect(toUnmodifiableMap(
		                method -> method,
		                method -> Stream.concat(
		                        stream(method.getAnnotationsByType(CheckBefore.class)),
		                        stream(method.getAnnotationsByType(CheckOneBefore.class))
		                                .flatMap(extractCheckOnBefore))
		                        .distinct()
		                        .collect(toUnmodifiableList())));

		final var allMethodsAuditsAfter = refererMethods.stream().collect(Collectors.toUnmodifiableMap(
		        method -> method,
		        method -> Stream.concat(
		                stream(method.getAnnotationsByType(AuditAfter.class)),
		                stream(method.getAnnotationsByType(AuditAllAfter.class))
		                        .flatMap(extractAuditAllAfter))
		                .distinct()
		                .collect(toUnmodifiableList())));

		allMethodsRenforceCheckBefore = refererMethods.stream()
		        .collect(toUnmodifiableMap(
		                method -> method,
		                method -> method.getAnnotationsByType(RenforceCheckBefore.class).length > 0));

		if (allClassCheckBefore.isEmpty()) {
			allMethodsRequireValidAuth = refererMethods.stream()
			        .collect(toUnmodifiableMap(
			                method -> method,
			                method -> allMethodsCheckBefore.get(method).isEmpty() == false));
		} else {
			/**
			 * Set all methods to true
			 */
			allMethodsRequireValidAuth = refererMethods.stream()
			        .collect(toUnmodifiableMap(
			                method -> method,
			                method -> true));
		}

		checkBeforeListByMethods = refererMethods.stream()
		        .collect(toUnmodifiableMap(
		                method -> method,
		                method -> Stream.concat(
		                        allClassCheckBefore.stream(),
		                        allMethodsCheckBefore.getOrDefault(method, List.of()).stream())
		                        .collect(toUnmodifiableList())));

		auditAfterListByMethods = refererMethods.stream()
		        .collect(toUnmodifiableMap(
		                method -> method,
		                method -> Stream.concat(
		                        allClassAuditsAfter.stream(),
		                        allMethodsAuditsAfter.getOrDefault(method, List.of()).stream())
		                        .collect(toUnmodifiableList())));

		controllerType = ControllerType.getFromClass(referer);
	}

	public List<CheckBefore> getRequireAuthList(final Method method) {
		return checkBeforeListByMethods.get(method);
	}

	public List<AuditAfter> getAudits(final Method method) {
		return auditAfterListByMethods.get(method);
	}

	public boolean isRequireRenforceCheckBefore(final Method method) {
		return allClassRenforceCheckBefore || allMethodsRenforceCheckBefore.getOrDefault(method, false);
	}

	public boolean isRequireValidAuth(final Method method) {
		return allMethodsRequireValidAuth.get(method);
	}

	public ControllerType getControllerType() {
		return controllerType;
	}

	public Stream<String> getAllRights() {
		return Stream.concat(
		        allClassCheckBefore.stream(),
		        allMethodsCheckBefore.values()
		                .stream()
		                .flatMap(List::stream))
		        .flatMap(cb -> Arrays.stream(cb.value()))
		        .distinct();
	}
}
