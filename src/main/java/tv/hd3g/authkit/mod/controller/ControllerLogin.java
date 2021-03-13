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
package tv.hd3g.authkit.mod.controller;

import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static org.springframework.context.i18n.LocaleContextHolder.getLocale;

import java.time.Duration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import tv.hd3g.authkit.mod.ControllerInterceptor;
import tv.hd3g.authkit.mod.dto.LoginRequestContentDto;
import tv.hd3g.authkit.mod.dto.validated.LoginFormDto;
import tv.hd3g.authkit.mod.dto.validated.ResetPasswordFormDto;
import tv.hd3g.authkit.mod.dto.validated.TOTPLogonCodeFormDto;
import tv.hd3g.authkit.mod.exception.BlockedUserException;
import tv.hd3g.authkit.mod.exception.NotAcceptableSecuredTokenException;
import tv.hd3g.authkit.mod.exception.ResetWithSamePasswordException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.TOTPUserCantLoginException;
import tv.hd3g.authkit.mod.exception.UserCantLoginException.UserMustChangePasswordException;
import tv.hd3g.authkit.mod.service.AuthenticationService;
import tv.hd3g.authkit.mod.service.CookieService;
import tv.hd3g.authkit.mod.service.SecuredTokenService;
import tv.hd3g.commons.authkit.AuditAfter;
import tv.hd3g.commons.authkit.CheckBefore;

@Controller
public class ControllerLogin {

	public static final String TOKEN_FORMNAME_LOGIN = "login";
	public static final String TOKEN_FORMNAME_RESET_PSD = "reset-password";
	public static final String TOKEN_FORMNAME_ENTER_TOTP = "totp-code";
	public static final String TOKEN_REDIRECT_RESET_PSD = "rpasswd";

	private static final String BOUNCETO = "bounceto";
	private static final String TMPL_NAME_LOGIN = "login";
	private static final String TMPL_NAME_RESET_PSD = "reset-password";
	private static final String TMPL_NAME_TOTP = "totp-challenge";
	private static final String TMPL_ATTR_ERROR = "error";
	private static final String TMPL_ATTR_FORMTOKEN = "formtoken";

	@Autowired
	private SecuredTokenService tokenService;
	@Autowired
	private MessageSource messageSource;
	@Autowired
	private AuthenticationService authenticationService;
	@Autowired
	private CookieService cookieService;

	@Value("${authkit.maxLoginTime:5m}")
	private Duration expirationDuration;
	@Value("${authkit.redirectToAfterLogin:/}")
	private String redirectToAfterLogin;
	@Value("${authkit.redirectToAfterLogout:/login}")
	private String redirectToAfterLogout;

	private String makeToken() {
		return tokenService.simpleFormGenerateToken(TOKEN_FORMNAME_LOGIN, expirationDuration);
	}

	@GetMapping("/login")
	public String login(final Model model) {
		model.addAttribute(TMPL_ATTR_FORMTOKEN, makeToken());
		return TMPL_NAME_LOGIN;
	}

	@PostMapping("/login")
	@AuditAfter(useSecurity = true, value = "Auth login page")
	public String doLogin(final Model model,
	                      @ModelAttribute @Valid final LoginFormDto form,
	                      final BindingResult bindingResult,
	                      final HttpServletRequest request,
	                      final HttpServletResponse response) {

		if (bindingResult.hasErrors()) {
			return sendLoginBindingError(model, response);
		}

		try {
			tokenService.simpleFormCheckToken(TOKEN_FORMNAME_LOGIN, form.getSecuretoken());
			final var userSession = authenticationService.userLoginRequest(request, form);
			return prepareResponseAfterLogon(model, request, response, userSession);
		} catch (final NotAcceptableSecuredTokenException e) {
			return sendErrorExpiredFormTokenDuringLogin(model, response, e);
		} catch (final TOTPUserCantLoginException e) {
			/**
			 * User is not yet logged: need to enter a TOTP code
			 */
			final var userUUID = e.getUserUUID();
			final var token = tokenService.userFormGenerateToken(TOKEN_FORMNAME_ENTER_TOTP, userUUID,
			        expirationDuration);

			model.addAttribute("shorttime", form.getShorttime());
			model.addAttribute(TMPL_ATTR_FORMTOKEN, token);
			return TMPL_NAME_TOTP;
		} catch (final UserMustChangePasswordException e) {
			final var userUUID = e.getUserUUID();
			final var token = tokenService.userFormGenerateToken(TOKEN_FORMNAME_RESET_PSD, userUUID,
			        expirationDuration);
			model.addAttribute(TMPL_ATTR_FORMTOKEN, token);
			return TMPL_NAME_RESET_PSD;
		} catch (final UserCantLoginException e) {
			return sendErrorDisabledBlockedUserDuringLogin(model, response, e);
		}
	}

	@GetMapping("/logout")
	@CheckBefore
	public String logout(final Model model, final HttpServletResponse response) {
		final var cookie = cookieService.deleteLogonCookie();
		cookie.setSecure(true);
		response.addCookie(cookie);

		model.addAttribute(BOUNCETO, ServletUriComponentsBuilder
		        .fromCurrentContextPath()
		        .path(redirectToAfterLogout)
		        .toUriString());
		return "bounce-logout";
	}

	@GetMapping("/reset-password/{token}")
	public String resetPassword(@PathVariable("token") @NotEmpty final String token,
	                            final Model model,
	                            final HttpServletRequest request,
	                            final HttpServletResponse response) {
		final String userUUID;
		try {
			userUUID = tokenService.securedRedirectRequestExtractToken(token, TOKEN_REDIRECT_RESET_PSD);
		} catch (final NotAcceptableSecuredTokenException e) {
			/**
			 * Invalid/expired token
			 */
			response.setStatus(SC_BAD_REQUEST);
			model.addAttribute(TMPL_ATTR_FORMTOKEN, makeToken());
			return TMPL_NAME_LOGIN;
		}

		final var userFormToken = tokenService.userFormGenerateToken(
		        TOKEN_FORMNAME_RESET_PSD, userUUID, expirationDuration);
		model.addAttribute(TMPL_ATTR_FORMTOKEN, userFormToken);
		return TMPL_NAME_RESET_PSD;
	}

	@PostMapping("/reset-password")
	@AuditAfter(useSecurity = true, value = "Reset password", changeSecurity = true)
	public String doResetPassword(final Model model,
	                              @ModelAttribute @Valid final ResetPasswordFormDto form,
	                              final BindingResult bindingResult,
	                              final HttpServletRequest request,
	                              final HttpServletResponse response) {

		if (bindingResult.hasErrors()) {
			response.setStatus(SC_BAD_REQUEST);
			final var errorMessage = messageSource.getMessage("authkit.reset-password.form-error", null,
			        getLocale());
			model.addAttribute(TMPL_ATTR_ERROR, errorMessage);
			model.addAttribute(TMPL_ATTR_FORMTOKEN, form.getSecuretoken());
			return TMPL_NAME_RESET_PSD;
		} else if (form.checkSamePasswords() == false) {
			response.setStatus(SC_BAD_REQUEST);
			final var errorMessage = messageSource.getMessage("authkit.reset-password.form-error.notsamepass", null,
			        getLocale());
			model.addAttribute(TMPL_ATTR_ERROR, errorMessage);
			model.addAttribute(TMPL_ATTR_FORMTOKEN, form.getSecuretoken());
			return TMPL_NAME_RESET_PSD;
		}

		try {
			final var userUUID = tokenService.userFormExtractTokenUUID(TOKEN_FORMNAME_RESET_PSD, form.getSecuretoken());
			authenticationService.changeUserPassword(userUUID, form.getNewuserpassword());
		} catch (final ResetWithSamePasswordException e) {
			response.setStatus(SC_BAD_REQUEST);
			final var errorMessage = messageSource.getMessage("authkit.reset-password.invalidpassword", null,
			        getLocale());
			model.addAttribute(TMPL_ATTR_ERROR, errorMessage);
			model.addAttribute(TMPL_ATTR_FORMTOKEN, form.getSecuretoken());
			return TMPL_NAME_RESET_PSD;
		} catch (final BlockedUserException e) {
			response.setStatus(SC_UNAUTHORIZED);
			final var errorMessage = messageSource.getMessage("authkit.reset-password.blockeduser", null, getLocale());
			model.addAttribute(TMPL_ATTR_ERROR, errorMessage);
			model.addAttribute(TMPL_ATTR_FORMTOKEN, makeToken());
			return TMPL_NAME_LOGIN;
		} catch (final NotAcceptableSecuredTokenException e) {
			response.setStatus(SC_BAD_REQUEST);
			final var errorMessage = messageSource.getMessage("authkit.reset-password.form-error", null, getLocale());
			model.addAttribute(TMPL_ATTR_ERROR, errorMessage);
			model.addAttribute(TMPL_ATTR_FORMTOKEN, makeToken());
			return TMPL_NAME_LOGIN;
		}

		final var doneMessage = messageSource.getMessage("authkit.reset-password.done", null, getLocale());
		model.addAttribute("actionDone", doneMessage);
		model.addAttribute(TMPL_ATTR_FORMTOKEN, makeToken());
		return TMPL_NAME_LOGIN;
	}

	@PostMapping("/login-2auth")
	@AuditAfter(useSecurity = true, value = "TOTP Logon", changeSecurity = false)
	public String doTOTPLogin(final Model model,
	                          @ModelAttribute @Valid final TOTPLogonCodeFormDto totpForm,
	                          final BindingResult bindingResult,
	                          final HttpServletRequest request,
	                          final HttpServletResponse response) {
		if (bindingResult.hasErrors()) {
			return sendLoginBindingError(model, response);
		}

		try {
			final var userSession = authenticationService.userLoginRequest(request, totpForm);
			return prepareResponseAfterLogon(model, request, response, userSession);
		} catch (final NotAcceptableSecuredTokenException e) {
			return sendErrorExpiredFormTokenDuringLogin(model, response, e);
		} catch (final UserCantLoginException e) {
			return sendErrorDisabledBlockedUserDuringLogin(model, response, e);
		}
	}

	private String sendLoginBindingError(final Model model, final HttpServletResponse response) {
		response.setStatus(SC_BAD_REQUEST);
		final var errorMessage = messageSource.getMessage("authkit.login.form-error", null, getLocale());
		model.addAttribute(TMPL_ATTR_ERROR, errorMessage);
		model.addAttribute(TMPL_ATTR_FORMTOKEN, makeToken());
		return TMPL_NAME_LOGIN;
	}

	private String prepareResponseAfterLogon(final Model model,
	                                         final HttpServletRequest request,
	                                         final HttpServletResponse response,
	                                         final LoginRequestContentDto userSession) {
		model.addAttribute("jwtsession", userSession.getUserSessionToken());
		final var cookie = userSession.getUserSessionCookie();
		cookie.setSecure(true);
		response.addCookie(cookie);

		final var oUserRedirectTo = ControllerInterceptor.getPathToRedirectToAfterLogin(request);
		if (oUserRedirectTo.isPresent()) {
			final var redirectAfterLoginCookie = cookieService.deleteRedirectAfterLoginCookie();
			redirectAfterLoginCookie.setSecure(true);
			response.addCookie(redirectAfterLoginCookie);
		}

		final var redirectTo = oUserRedirectTo
		        .map(path -> {
			        final var builder = ServletUriComponentsBuilder.fromCurrentRequest();
			        final var qMark = path.indexOf("?");
			        if (qMark > 0 && qMark + 1 < path.length()) {
				        return builder
				                .replacePath(path.substring(0, qMark))
				                .query(path.substring(qMark + 1));
			        } else {
				        return builder.replacePath(path);
			        }
		        })
		        .map(UriComponentsBuilder::toUriString)
		        .orElseGet(() -> ServletUriComponentsBuilder
		                .fromCurrentContextPath()
		                .path(redirectToAfterLogin)
		                .toUriString());

		model.addAttribute(BOUNCETO, redirectTo);
		return "bounce-session";
	}

	/**
	 * Invalid/expired form token
	 */
	private String sendErrorExpiredFormTokenDuringLogin(final Model model,
	                                                    final HttpServletResponse response,
	                                                    final NotAcceptableSecuredTokenException e) {
		response.setStatus(SC_BAD_REQUEST);
		final var errorMessage = messageSource.getMessage(e.getClass().getSimpleName(), null, getLocale());
		model.addAttribute(TMPL_ATTR_ERROR, errorMessage);
		model.addAttribute(TMPL_ATTR_FORMTOKEN, makeToken());
		return TMPL_NAME_LOGIN;
	}

	/**
	 * Bad User login/password or disabled/blocked user.
	 * Bad Code (TOTP), disabled/blocked user.
	 */
	private String sendErrorDisabledBlockedUserDuringLogin(final Model model,
	                                                       final HttpServletResponse response,
	                                                       final UserCantLoginException e) {
		response.setStatus(e.getHttpReturnCode());
		final var errorMessage = messageSource.getMessage(e.getClass().getSimpleName(), null, getLocale());
		model.addAttribute(TMPL_ATTR_ERROR, errorMessage);
		model.addAttribute(TMPL_ATTR_FORMTOKEN, makeToken());
		return TMPL_NAME_LOGIN;
	}

}
