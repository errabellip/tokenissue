package com.errabelli.token.saml.validator.controller;

import static org.springframework.hateoas.mvc.ControllerLinkBuilder.linkTo;
import static org.springframework.hateoas.mvc.ControllerLinkBuilder.methodOn;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.hateoas.Link;
import org.springframework.hateoas.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.errabelli.api.exception.BusinessException;
import com.errabelli.token.saml.validator.beans.SamlResponseExtract;
import com.errabelli.token.saml.validator.util.SamlExtractor;
import com.errabelli.token.service.security.util.JwtTokenValidator;
import com.errabelli.token.service.security.util.SecurityConstant;

import io.swagger.annotations.ApiOperation;

@RestController
@RequestMapping("/saml/validator/${token.saml.validator.api.version}")
public class SamlValidatorController {

	private static final String REFERER = "Referer";

	private static final Logger logger = LoggerFactory.getLogger(SamlValidatorController.class);

	@Autowired
	private JwtTokenValidator jwtTokenValidator;

	@Autowired
	private SamlExtractor validator;

	@ApiOperation(value = "verifySamlResponse", notes = "This service validates SAML Response for the given issuer, extracts and returns assertion attributes", nickname = "SAML Validator")
	@RequestMapping(method = RequestMethod.POST, consumes = "text/xml")
	public Resource<SamlResponseExtract> verifySamlResponse(@RequestParam(name = "issuer", required = true) String issuer,
			@RequestBody String samlResponse, @RequestHeader("Authorization") String authorizationToken,
			HttpServletRequest request) {

		logger.debug("Entered SamlValidatorController.verifySamlResponse : Issuer={}, Body={}", issuer, samlResponse);

		// swagger check
		if (logger.isDebugEnabled()) {
			logger.debug("Referer == {}", request.getHeader(REFERER));
			logger.debug("requestURI =={}", request.getRequestURI());
		}

		if (request.getHeader(REFERER) != null && !request.getHeader(REFERER).endsWith(SecurityConstant.SWAGGER_HTML)
				|| request.getHeader(REFERER) == null) {

			// remove schema from token
			if (authorizationToken.indexOf("Bearer") == -1) {
				throw new BusinessException("getAuthorizationKey: Authorization schema not found",
						"getAuthorizationKey: Authorization schema not found", HttpStatus.INTERNAL_SERVER_ERROR);
			}

			// Parse and verify JWT token
			String jwtToken = authorizationToken.substring("Bearer".length()).trim();
			jwtTokenValidator.validateWithoutParam(jwtToken);
		}

		// Validation of input
		if (samlResponse == null || !samlResponse.trim().startsWith("SAMLResponse=")) {
			throw new BusinessException("SAMLValidator: Valid SAML Response is expected in the request",
					"SAMLValidator: Valid SAML Response is expected in the request", HttpStatus.BAD_REQUEST);
		}
		String samlStringEncoded = samlResponse.substring("SAMLResponse=".length()).trim();

		// Validation of issuer
		if (issuer == null) {
			throw new BusinessException("SAMLValidator: Valid issuer is expected in the request",
					"SAMLValidator: Valid issuer is expected in the request", HttpStatus.BAD_REQUEST);
		}

		SamlResponseExtract extract = validator.processSamlResponse(samlStringEncoded, issuer);

		return processSuccessHateoasResponse(extract, issuer, samlResponse, authorizationToken, request);
	}

	private Resource<SamlResponseExtract> processSuccessHateoasResponse(
			SamlResponseExtract samlResponseExtract, String issuer, String samlResponse, String authorizationToken,
			HttpServletRequest request) {

		Link selfLink = linkTo(methodOn(SamlValidatorController.class).verifySamlResponse(issuer, samlResponse, authorizationToken, request)).withSelfRel();
		return new Resource<SamlResponseExtract>(samlResponseExtract, selfLink);
	}
}