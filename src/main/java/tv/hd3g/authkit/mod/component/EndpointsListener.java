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
package tv.hd3g.authkit.mod.component;

import static java.util.Arrays.stream;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import tv.hd3g.commons.authkit.AuditAfter;
import tv.hd3g.commons.authkit.AuditAllAfter;
import tv.hd3g.commons.authkit.CheckBefore;
import tv.hd3g.commons.authkit.CheckOneBefore;
import tv.hd3g.commons.authkit.RenforceCheckBefore;

@Component
public class EndpointsListener implements ApplicationListener<ApplicationEvent> {

	private final ConcurrentHashMap<Class<?>, AnnotatedClass> annotationCache;

	public EndpointsListener() {
		annotationCache = new ConcurrentHashMap<>();
	}

	@Override
	public void onApplicationEvent(final ApplicationEvent event) {
		if (event instanceof ContextRefreshedEvent) {
			((ContextRefreshedEvent) event).getApplicationContext()
			        .getBean(RequestMappingHandlerMapping.class)
			        .getHandlerMethods().values().stream()
			        .map(HandlerMethod::getBeanType).forEach(this::getAnnotatedClass);
		}
	}

	public Set<String> getAllRights() {
		return annotationCache.values().stream().flatMap(ac -> {
			final var cl = ac.allClassCheckBefore.stream();
			final var mc = ac.allMethodsCheckBefore.values().stream().flatMap(List::stream);
			return Stream.concat(cl, mc);
		}).flatMap(cb -> Arrays.stream(cb.value())).distinct().collect(Collectors.toUnmodifiableSet());
	}

	public AnnotatedClass getAnnotatedClass(final Class<?> controllerClass) {
		return annotationCache.computeIfAbsent(controllerClass, AnnotatedClass::new);
	}

	public class AnnotatedClass {

		private final List<CheckBefore> allClassCheckBefore;
		private final Map<Method, List<CheckBefore>> allMethodsCheckBefore;
		private final List<AuditAfter> allClassAuditsAfter;
		private final Map<Method, List<AuditAfter>> allMethodsAuditsAfter;
		private final boolean allClassRenforceCheckBefore;
		private final Map<Method, Boolean> allMethodsRenforceCheckBefore;

		private AnnotatedClass(final Class<?> referer) {
			final Function<CheckOneBefore, Stream<CheckBefore>> extractCheckOnBefore = audits -> stream(audits.value());
			final Function<AuditAllAfter, Stream<AuditAfter>> extractAuditAllAfter = audits -> stream(audits.value());

			allClassCheckBefore = Stream.concat(
			        stream(referer.getAnnotationsByType(CheckBefore.class)),
			        stream(referer.getAnnotationsByType(CheckOneBefore.class)).flatMap(extractCheckOnBefore))
			        .distinct().collect(Collectors.toUnmodifiableList());
			allClassAuditsAfter = Stream.concat(
			        stream(referer.getAnnotationsByType(AuditAfter.class)),
			        stream(referer.getAnnotationsByType(AuditAllAfter.class)).flatMap(extractAuditAllAfter))
			        .distinct().collect(Collectors.toUnmodifiableList());
			allClassRenforceCheckBefore = referer.getAnnotationsByType(RenforceCheckBefore.class).length > 0;
			allMethodsCheckBefore = stream(referer.getMethods()).collect(Collectors.toUnmodifiableMap(
			        method -> method,
			        method -> Stream.concat(
			                stream(method.getAnnotationsByType(CheckBefore.class)),
			                stream(method.getAnnotationsByType(CheckOneBefore.class)).flatMap(extractCheckOnBefore))
			                .distinct().collect(Collectors.toUnmodifiableList())));
			allMethodsAuditsAfter = stream(referer.getMethods()).collect(Collectors.toUnmodifiableMap(
			        method -> method,
			        method -> Stream.concat(
			                stream(method.getAnnotationsByType(AuditAfter.class)),
			                stream(method.getAnnotationsByType(AuditAllAfter.class)).flatMap(extractAuditAllAfter))
			                .distinct().collect(Collectors.toUnmodifiableList())));
			allMethodsRenforceCheckBefore = stream(referer.getMethods()).collect(Collectors.toUnmodifiableMap(
			        method -> method,
			        method -> method.getAnnotationsByType(RenforceCheckBefore.class).length > 0));
		}

		public List<CheckBefore> requireAuthList(final Method method) {
			return Stream.concat(
			        allClassCheckBefore.stream(),
			        allMethodsCheckBefore.getOrDefault(method, List.of()).stream())
			        .collect(Collectors.toUnmodifiableList());
		}

		public List<AuditAfter> getAudits(final Method method) {
			return Stream.concat(
			        allClassAuditsAfter.stream(),
			        allMethodsAuditsAfter.getOrDefault(method, List.of()).stream())
			        .collect(Collectors.toUnmodifiableList());
		}

		public boolean isRequireRenforceCheckBefore(final Method method) {
			return allClassRenforceCheckBefore || allMethodsRenforceCheckBefore.getOrDefault(method, false);
		}
	}

}