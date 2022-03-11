package com.errabelli.token.saml.pietech.controller;

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
import com.errabelli.token.saml.pietech.beans.PietechSamlToken;
import com.errabelli.token.saml.pietech.beans.PietechSamlTokenApiResponse;
import com.errabelli.token.saml.pietech.util.SamlTokenGenerator;
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
@RequestMapping("/saml/pietech/${token.saml.pietech.api.version}")
public class SamlTokenIssuerController {

	private static final String REFERER = "Referer";

	@Autowired
	SamlTokenGenerator samlTokenGenerator;

	@Autowired
	private JwtTokenValidator jwtTokenValidator;

	private static final Logger logger = LoggerFactory.getLogger(SamlTokenIssuerController.class);

	@ApiOperation(value = "GET SAML Token for PieTech", notes = "This service provides SAML token to be used to post to PIEtech", nickname = "GetPietechSamlToken")

	@RequestMapping(value = "/{guestId}/{planId}/{entitlements}", method = RequestMethod.GET, produces = "application/hal+json")
	public Resource<PietechSamlTokenApiResponse> generateSamlToken(@PathVariable("guestId") String ciscin, @PathVariable("planId") String planId, @PathVariable("entitlements") String entitlements, 
			 @RequestHeader("Authorization") String authorizationToken, HttpServletRequest request) {

		logger.debug("Entered SamlTokenIssuerController.generateSamlToken :{}", ciscin);
		
		//validate CISCIN
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
			// Validate CISCIN
			String jwtToken = authorizationToken.substring("Bearer".length()).trim();
			
			jwtTokenValidator.validateCiscinParam(jwtToken, ciscin);
		}

		/**String token = "<?xml version='1.0' encoding='UTF-8'?><saml2p:Response xmlns:saml2p='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:xsd='http://www.w3.org/2001/XMLSchema' Destination='https://moneyguidepro-URL-goes-here' ID='_45044271-3d6d-460f-8801-15d901288d46' IssueInstant='2017-08-01T04:38:53.434Z' Version='2.0'><ds:Signature xmlns:ds='http://www.w3.org/2000/09/xmldsig#'><ds:SignedInfo><ds:CanonicalizationMethod Algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315'/><ds:SignatureMethod Algorithm='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'/><ds:Reference URI='#_45044271-3d6d-460f-8801-15d901288d46'><ds:Transforms><ds:Transform Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature'/><ds:Transform Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'><ec:InclusiveNamespaces xmlns:ec='http://www.w3.org/2001/10/xml-exc-c14n#' PrefixList='xsd'/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm='http://www.w3.org/2001/04/xmlenc#sha256'/><ds:DigestValue>sXZ56r2Sdj3YJ3B/zfAPVnNN/QGQaIples+EmgszEMA=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>t5WbfMFaRNHCEPriTCUdnr1c3sopHx2DwXkk8bS5sax7fRzcEIkH8cWl4EjonLT14jGjPCgwHOPgc1wNXd3qNYXvcJIucWatKGiL7hRBpaXDOSbb3z7+/6LLxOQ8qS/E9Sv6l3HLw/BHtPfxp1nL7zf8vPVpYM38wzXLkTitvWwtYU2S2AgDqIDj6L74Ys+i/YVnPfvb8Zy6FQ+Ut5fB1g8lMy7zDuiq93irvRGXe8esLR6DXBods+8BrJgoT2mURHbQv4+ElAs9DZ8PdrTFG7qZI2ZDesWskvxN849fwDPIantyF9Xray1tTJIqRc2C81fA8O6zgbs3WQgBPsYMpQ==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>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</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2p:Status><saml2p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></saml2p:Status><saml2:Assertion xmlns:saml2='urn:oasis:names:tc:SAML:2.0:assertion' ID='_e0c95be5-cd44-49f6-b3af-9f7b6fdc53c7' IssueInstant='2017-08-01T04:38:53.498Z' Version='2.0'><saml2:Issuer>SunTrust Bank</saml2:Issuer><saml2:Subject><saml2:NameID Format='urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'>HouseholdId-goes-here</saml2:NameID><saml2:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'><saml2:SubjectConfirmationData NotBefore='2017-08-01T04:38:53.500Z' NotOnOrAfter='2017-08-01T04:53:53.500Z' Recipient='https://moneyguidepro-URL-goes-here'/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore='2017-08-01T04:38:53.503Z' NotOnOrAfter='2017-08-01T04:53:53.503Z'><saml2:AudienceRestriction><saml2:Audience>https://moneyguidepro-URL-goes-here</saml2:Audience></saml2:AudienceRestriction><saml2:OneTimeUse/></saml2:Conditions><saml2:AuthnStatement AuthnInstant='2017-08-01T04:38:53.505Z'><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement><saml2:Attribute Name='GuestID'><saml2:AttributeValue xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xsi:type='xsd:string'>CISCIN</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name='HouseholdId'><saml2:AttributeValue xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xsi:type='xsd:string'>HouseholdId-goes-here</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name='Entitlements'><saml2:AttributeValue xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xsi:type='xsd:string'>mymgp</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion></saml2p:Response>"; **/
		String token = samlTokenGenerator.createToken(ciscin, planId, entitlements);
		String mgpSsoUrl = samlTokenGenerator.getMgpURL(entitlements);
		PietechSamlTokenApiResponse samlTokenResponse = new PietechSamlTokenApiResponse(new PietechSamlToken(token, mgpSsoUrl));
		return processSuccessHateoasResponse(samlTokenResponse, ciscin, planId, entitlements, authorizationToken, request);
	}

	private Resource<PietechSamlTokenApiResponse> processSuccessHateoasResponse(PietechSamlTokenApiResponse samlTokenResponse,
			String ciscin, String planId, String entitlements, String authorizationToken, HttpServletRequest request) {

		Link selfLink = linkTo(
				methodOn(SamlTokenIssuerController.class).generateSamlToken(ciscin, planId, entitlements, authorizationToken, request))
						.withSelfRel();
		return new Resource<>(samlTokenResponse, selfLink);
	}
}
