package com.errabelli.token.saml.ir.controller;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.errabelli.api.exception.BusinessException;
import com.errabelli.token.saml.ir.beans.SamlAssertionResponse;
import com.errabelli.token.saml.ir.util.SamlAssertionGenerator;
import com.errabelli.token.service.security.util.JwtTokenValidator;
import com.errabelli.token.service.security.util.SecurityConstant;

@RestController
@RequestMapping("/saml/IR/${token.saml.ir.api.version}")
public class SamlAssertionIssuerController {

	private static final String REFERER = "Referer";

	@Autowired
	private SamlAssertionGenerator samlAssertionGenerator;

	@Autowired
	private JwtTokenValidator jwtTokenValidator;

	@Autowired
	private HttpServletRequest httpRequest;

	private static final Logger logger = LoggerFactory.getLogger(SamlAssertionIssuerController.class);

	@RequestMapping(value = "/{entity}/{username}/{portalCompanyId}", method = RequestMethod.GET, produces = "application/hal+json")
	public SamlAssertionResponse getSamlAssertion(@PathVariable("entity") String entity,
			@PathVariable("username") String username, @PathVariable("portalCompanyId") String portalCompanyId,
			@RequestHeader("Authorization") String authorizationToken) {
		logger.debug("Entered SamlTokenIssuerController.generateSamlToken :{}", entity);

		// swagger check
		if (logger.isDebugEnabled()) {
			logger.debug("Referer == {}", httpRequest.getHeader(REFERER));
			logger.debug("requestURI =={}", httpRequest.getRequestURI());
		}
		if ((httpRequest.getHeader(REFERER) != null
				&& !httpRequest.getHeader(REFERER).endsWith(SecurityConstant.SWAGGER_HTML)
				|| (httpRequest.getHeader(REFERER) == null && !portalCompanyId.equalsIgnoreCase("test")))) {

			// remove schema from token

			if (authorizationToken.indexOf("Bearer") == -1) {
				throw new BusinessException("getAuthorizationKey: Authorization schema not found",
						"getAuthorizationKey: Authorization schema not found", HttpStatus.INTERNAL_SERVER_ERROR);
			}

			String jwtToken = authorizationToken.substring("Bearer".length()).trim();

			jwtTokenValidator.validateOtherParam(jwtToken, "tusercompanyid", portalCompanyId);

		}
		return samlAssertionGenerator.createSamlAssertion(entity, username);
	}
}
