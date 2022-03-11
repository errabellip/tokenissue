package com.errabelli.token.saml.tsys.controller;

import static org.springframework.hateoas.mvc.ControllerLinkBuilder.linkTo;
import static org.springframework.hateoas.mvc.ControllerLinkBuilder.methodOn;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.hateoas.Link;
import org.springframework.hateoas.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.errabelli.api.exception.BusinessException;
import com.errabelli.token.saml.beans.SamlToken;
import com.errabelli.token.saml.beans.SamlTokenApiResponse;
import com.errabelli.token.saml.tsys.util.TsysSamlTokenGenerator;
import com.errabelli.token.service.security.util.JwtTokenValidator;
import com.errabelli.token.service.security.util.SecurityConstant;

import io.swagger.annotations.ApiOperation;

/**
 * @author ugck118
 *
 *         Main Controller to control requests for SAML token generation
 * 
 */
@RestController
@RequestMapping("/saml/tsys/${token.saml.tsys.api.version}")
public class TsysSamlTokenIssuerController {

	private static final String REFERER = "Referer";

	@Autowired
	TsysSamlTokenGenerator tsysSamlTokenGenerator;

	@Autowired
	private JwtTokenValidator jwtTokenValidator;

	private static final Logger logger = LoggerFactory.getLogger(TsysSamlTokenIssuerController.class);

	@ApiOperation(value = "GET SAML Token for TSYS", notes = "This service provides SAML token to be used to post to TSYS", nickname = "GetTsysSamlToken")

	@RequestMapping(value = "/{crfcin}", method = RequestMethod.GET, produces = "application/hal+json")
	public Resource<SamlTokenApiResponse> generateSamlToken(@PathVariable("crfcin") String crfcin,
			 @RequestHeader("Authorization") String authorizationToken, HttpServletRequest request) {

		logger.debug("Entered TsysSamlTokenIssuerController.generateSamlToken :{}", crfcin);
		
		// swagger check
		if (logger.isDebugEnabled()) {
			logger.debug("Referer == {}" ,request.getHeader(REFERER));
			logger.debug("requestURI =={}" ,request.getRequestURI());
		}

		if (request.getHeader(REFERER) != null && !request.getHeader(REFERER).endsWith(SecurityConstant.SWAGGER_HTML)
				|| request.getHeader(REFERER) == null) {
			
			// remove schema from token
			if (authorizationToken.indexOf("Bearer") == -1) {
				throw new BusinessException("getAuthorizationKey: Authorization schema not found",
						"getAuthorizationKey: Authorization schema not found", HttpStatus.INTERNAL_SERVER_ERROR);
			}

			// Validate nameId
			String jwtToken = authorizationToken.substring("Bearer".length()).trim();
			jwtTokenValidator.validateOtherParam(jwtToken, "t_crfcin", crfcin);
		}

		/**String token = "<?xml version='1.0' encoding='UTF-8'?><samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:dsig='http://www.w3.org/2000/09/xmldsig#' xmlns:enc='http://www.w3.org/2001/04/xmlenc#' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' xmlns:x500='urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' Destination='https://rewardstsys-test.suntrust.com/landing.htm' ID='id-wdnoeCv4Z-OzbWcUVwW1iyDyKTbVnTLdi2Hp83-9' IssueInstant='2018-09-20T19:20:24Z' Version='2.0'><saml:Issuer Format='urn:oasis:names:tc:SAML:2.0:nameid-format:entity'>https://itca_federation.suntrust.com</saml:Issuer><samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success' /></samlp:Status><saml:Assertion ID='id-5lxKD7pIJdIi5PRs5F-hBW1fn-SWq7pYP71ntGZb' IssueInstant='2018-09-20T19:20:24Z' Version='2.0'><saml:Issuer Format='urn:oasis:names:tc:SAML:2.0:nameid-format:entity'>https://itca_federation.suntrust.com</saml:Issuer><dsig:Signature><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#' /><dsig:SignatureMethod Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1' /><dsig:Reference URI='#id-5lxKD7pIJdIi5PRs5F-hBW1fn-SWq7pYP71ntGZb'><dsig:Transforms><dsig:Transform Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature' /><dsig:Transform Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#' /></dsig:Transforms><dsig:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1' /><dsig:DigestValue>n1APn4YRydAgOJb2on2wDGMWhew=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>ba7tGcAUNYSJzhu34/SoJUH9n3JYE4m27My6Ro2/T4CMMrjpmqg22k+VJrvfgiUuamwnmjjUqWetjfg3GUo7LJ7jqg2xsZfRH5Dx8MGoCimI67hHzX8y1Io+jLM6C8c/DwclCJJyNzI/tIAF4Z+I4vLyUwluElB/nxw0dotfGlEs7OqtPQRLeb5WQvNa+315t6a59J9rz87YaTiMxIttXvfogg81rOE830r6JcOQydJ2/tubBLrvwL/enGN7eeHWdgMiGFfXfw5o81/zTMkQVtE+JBgknJtKsBJw6FxxZ968N2gf2M/uXP1YDba7Ib4lBuIjQaZLhIQP7Z6GW11xew==</dsig:SignatureValue></dsig:Signature><saml:Subject><saml:NameID Format='orafed-custom'>00185496106</saml:NameID><saml:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'><saml:SubjectConfirmationData NotOnOrAfter='2018-09-20T19:25:24Z' Recipient='https://rewardstsys-test.suntrust.com/landing.htm' /></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore='2018-09-20T19:20:24Z' NotOnOrAfter='2018-09-20T19:25:24Z'><saml:AudienceRestriction><saml:Audience>https://itca_federation.suntrust.com_tsys</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant='2018-09-20T19:18:57Z' SessionIndex='id-JJYLelov4bpqMg-JKe52zncfH7wKap4RREVmg8H0' SessionNotOnOrAfter='2018-09-20T20:20:24Z'><saml:AuthnContext><saml:AuthnContextClassRef>RETAIL_OnlineBanking_RememberMe</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>"; **/
		String token = tsysSamlTokenGenerator.createToken(crfcin);
		String ssoUrl = tsysSamlTokenGenerator.getSsoUrl();
		SamlTokenApiResponse samlTokenResponse = new SamlTokenApiResponse(new SamlToken(token, ssoUrl));
		return processSuccessHateoasResponse(samlTokenResponse, crfcin, authorizationToken, request);
	}

	private Resource<SamlTokenApiResponse> processSuccessHateoasResponse(SamlTokenApiResponse samlTokenResponse,
			String nameId, String authorizationToken, HttpServletRequest request) {

		Link selfLink = linkTo(
				methodOn(TsysSamlTokenIssuerController.class).generateSamlToken(nameId, authorizationToken, request))
						.withSelfRel();
		return new Resource<>(samlTokenResponse, selfLink);
	}
}
