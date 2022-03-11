package com.errabelli.token.saml.summitview.controller;

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
import com.errabelli.token.saml.summitview.util.SummitviewSamlTokenGenerator;
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
@RequestMapping("/saml/summitview/${token.saml.summitview.api.version}")
public class SummitviewSamlTokenIssuerController {

	private static final String REFERER = "Referer";

	@Autowired
	SummitviewSamlTokenGenerator summitviewSamlTokenGenerator;

	@Autowired
	private JwtTokenValidator jwtTokenValidator;

	private static final Logger logger = LoggerFactory.getLogger(SummitviewSamlTokenIssuerController.class);

	@ApiOperation(value = "GET SAML Token for SummitView", notes = "This service provides SAML token to be used to post to SummitView", nickname = "GetSummitViewSamlToken")

	@RequestMapping(value = "/{guid}/{applicationName}", method = RequestMethod.GET, produces = "application/hal+json")
	public Resource<SamlTokenApiResponse> generateSamlToken(@PathVariable("guid") String guid, @PathVariable("applicationName") String applicationName,
			 @RequestHeader("Authorization") String authorizationToken, HttpServletRequest request) {

		logger.debug("Entered SummitviewSamlTokenIssuerController.generateSamlToken : guid={}, applicationName={}", guid, applicationName);
		
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
			jwtTokenValidator.validateOtherParam(jwtToken, "tuserguid", guid);
		}

		/** String token = "<?xml version='1.0' encoding='UTF-8'?><samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:dsig='http://www.w3.org/2000/09/xmldsig#' xmlns:enc='http://www.w3.org/2001/04/xmlenc#' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' xmlns:x500='urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' Destination='https://externalbeta2.emaplan.com/suntrust/SSO/SelfIntegration/ACS' ID='id-QT3Yv8IaRW-iqGFZp1vSkb7kqP2BsR-E-QevQqbx' IssueInstant='2018-09-22T23:03:08Z' Version='2.0'><saml:Issuer Format='urn:oasis:names:tc:SAML:2.0:nameid-format:entity'>https://itca_federation.suntrust.com</saml:Issuer><samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success' /></samlp:Status><saml:Assertion ID='id-VFB-J9gXkFiSbbkceSsSlh5F-vKF--5d6eHKU5kx' IssueInstant='2018-09-22T23:03:08Z' Version='2.0'><saml:Issuer Format='urn:oasis:names:tc:SAML:2.0:nameid-format:entity'>https://itca_federation.suntrust.com</saml:Issuer><dsig:Signature><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#' /><dsig:SignatureMethod Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1' /><dsig:Reference URI='#id-VFB-J9gXkFiSbbkceSsSlh5F-vKF--5d6eHKU5kx'><dsig:Transforms><dsig:Transform Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature' /><dsig:Transform Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#' /></dsig:Transforms><dsig:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1' /><dsig:DigestValue>+3QCAPCwSx7DxyXFJuN43y3J770=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>ZZjDjsYNA26MSpEDGty37qk1Tk7cC6orxMaqdGGnkWT2P6c35LMIBN2Brbp9udHTBfjLX2uz9Ia5oduMsxfVZoIK8RvOklLAXSF4pI/FDyfw4P/5jbfhySt7s/hlJVHIRbsCyOGRCa2Rc6P8QZ79ZIF2A95Z3p4DQdV1EyNkk6RRVU9+GzcwbjctISC0JxsZsBG92OOB/lPp+ybN8GImpczeIdqwAORdX6CFjTUyEeprR0CI5Q1tXyxf6YVQS+YqMtmYt0GJABXVFn1jynOnFefR8UtWPpKJ17Y0ENqM7QkCgFemmp32/Mbwb3yGScilMoeaRdjvzwMAWKXCPtAlbw==</dsig:SignatureValue></dsig:Signature><saml:Subject><saml:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:custom'>abfe7b0c-a2f1-4fae-bd45-0a5489aad7ea</saml:NameID><saml:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'><saml:SubjectConfirmationData NotOnOrAfter='2018-09-22T23:09:08Z' Recipient='https://externalbeta2.emaplan.com/suntrust/SSO/SelfIntegration/ACS' /></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore='2018-09-22T23:02:08Z' NotOnOrAfter='2018-09-22T23:09:08Z'><saml:AudienceRestriction><saml:Audience>https://itca_federation.suntrust.com_summitview</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant='2018-09-22T23:02:26Z' SessionIndex='id-iU31Waxvrs6LInmmzbjwmJurvBZtLYgZtTkTJDtU' SessionNotOnOrAfter='2018-09-23T00:04:08Z'><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name='ApplicationName' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'><saml:AttributeValue xmlns:xs='http://www.w3.org/2001/XMLSchema' xsi:type='xs:string'>OnlineBanking</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>"; **/
		String token = summitviewSamlTokenGenerator.createToken(guid, applicationName);
		String ssoUrl = summitviewSamlTokenGenerator.getSsoUrl();
		SamlTokenApiResponse samlTokenResponse = new SamlTokenApiResponse(new SamlToken(token, ssoUrl));
		return processSuccessHateoasResponse(samlTokenResponse, guid, applicationName, authorizationToken, request);
	}

	private Resource<SamlTokenApiResponse> processSuccessHateoasResponse(SamlTokenApiResponse samlTokenResponse,
			String guid, String applicationName, String authorizationToken, HttpServletRequest request) {

		Link selfLink = linkTo(
				methodOn(SummitviewSamlTokenIssuerController.class).generateSamlToken(guid, applicationName, authorizationToken, request))
						.withSelfRel();
		return new Resource<>(samlTokenResponse, selfLink);
	}
}
