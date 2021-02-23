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
package tv.hd3g.authkit.mod;

import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

import java.util.Map;
import java.util.Optional;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import tv.hd3g.authkit.mod.exception.AuthKitException;
import tv.hd3g.authkit.utility.LogSanitizer;

/**
 * See https://www.toptal.com/java/spring-boot-rest-api-error-handling
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@ControllerAdvice
public class RestExceptionHandler extends ResponseEntityExceptionHandler {
	private static Logger log = LogManager.getLogger();

	@ExceptionHandler(AuthKitException.class)
	protected ResponseEntity<Object> handleRESTException(final AuthKitException e, final WebRequest request) {
		log.warn(() -> "REST Error for " + LogSanitizer.sanitize(request.getDescription(true)), e);
		return new ResponseEntity<>(Map.of("message",
		        Optional.ofNullable(e.getMessage()).orElse("(No message)")),
		        Optional.ofNullable(HttpStatus.resolve(e.getReturnCode())).orElse(INTERNAL_SERVER_ERROR));
	}
}
