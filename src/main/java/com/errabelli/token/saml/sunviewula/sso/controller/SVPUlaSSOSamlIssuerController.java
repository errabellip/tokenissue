package com.errabelli.token.saml.sunviewula.sso.controller;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.errabelli.api.exception.BusinessException;
import com.errabelli.token.saml.ir.beans.SamlAssertionResponse;
import com.errabelli.token.saml.sunviewula.sso.util.IPUlaSSOSamlGenerator;
import com.errabelli.token.saml.sunviewula.sso.util.IRUlaSSOSamlGenerator;
import com.errabelli.token.saml.sunviewula.sso.util.OLCUlaSSOSamlGenerator;
import com.errabelli.token.service.security.util.JwtTokenValidator;
import com.errabelli.token.service.security.util.SecurityConstant;

import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;

@RestController
@RequestMapping("/saml/svp/ula/${token.saml.ir.api.version}")
public class SVPUlaSSOSamlIssuerController {

	private static final String REFERER = "Referer";

	@Autowired
	private IRUlaSSOSamlGenerator irUlaSamlAssertionGenerator;

	@Autowired
	private IPUlaSSOSamlGenerator ipUlaSamlAssertionGenerator;

	@Autowired
	private OLCUlaSSOSamlGenerator olcUlaSamlAssertionGenerator;

	@Autowired
	private JwtTokenValidator jwtTokenValidator;

	@Autowired
	private HttpServletRequest httpRequest;

	private static final Logger logger = LoggerFactory.getLogger(SVPUlaSSOSamlIssuerController.class);

	@ApiOperation(value = "Retrieves the SAML Token for IR/IP/OLC ULA's of Sunview Portal", notes = "", response = SamlAssertionResponse.class, tags = {
			"Sunview ULA's SAML Controller", })
	@RequestMapping(value = "{portalCompanyId}/{ulaName}", method = RequestMethod.GET, produces = "application/hal+json")
	public SamlAssertionResponse getSamlAssertion(
			@ApiParam(value = "ULA Name - IR/IP/OLC") @PathVariable("ulaName") String ulaName,
			@ApiParam(value = "PortalCompanyID for JWT validation") @PathVariable("portalCompanyId") String portalCompanyId,
			@ApiParam(value = "entiy name - required for IR ula") @RequestParam(value = "entity", required = false) String entity,
			@ApiParam(value = "user name - required for IR ula") @RequestParam(value = "userName", required = false) String userName,
			@ApiParam(value = "guid - required for IP&OLC ula") @RequestParam(value = "guid", required = false) String userGuid,
			@ApiParam(value = "OLC Attribute Name - required for OLC ula") @RequestParam(value = "olcAttrName", required = false) String olcAttrName,
			@ApiParam(value = "OLC Attribute value - required for OLC ula") @RequestParam(value = "olcAttrValue", required = false) String olcAttrValue,
			@ApiParam(value = "Authorization contains JWT for validating the request source") @RequestHeader("Authorization") String authorizationToken) {
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

		if ("IR".equalsIgnoreCase(ulaName)) {
			return irUlaSamlAssertionGenerator.createSamlResponse(entity, userName);
		} else if ("IP".equalsIgnoreCase(ulaName)) {
			return ipUlaSamlAssertionGenerator.createSamlResponse(userGuid);
		} else if ("OLC".equalsIgnoreCase(ulaName)) {
			return olcUlaSamlAssertionGenerator.createSamlResponse(userGuid, olcAttrName, olcAttrValue);
		}
		return null;
	}
}
