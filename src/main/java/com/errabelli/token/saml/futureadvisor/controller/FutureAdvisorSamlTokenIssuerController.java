package com.errabelli.token.saml.futureadvisor.controller;

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
import com.errabelli.token.saml.futureadvisor.util.FutureAdvisorSamlTokenGenerator;
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
@RequestMapping("/saml/futureadvisor/${token.saml.futureadvisor.api.version}")
public class FutureAdvisorSamlTokenIssuerController {

	private static final String REFERER = "Referer";

	@Autowired
	FutureAdvisorSamlTokenGenerator futureAdvisorSamlTokenGenerator;

	@Autowired
	private JwtTokenValidator jwtTokenValidator;

	private static final Logger logger = LoggerFactory.getLogger(FutureAdvisorSamlTokenIssuerController.class);

	@ApiOperation(value = "GET SAML Token for FutureAdvisor", notes = "This service provides SAML token to be used to post to FutureAdvisor", nickname = "GetFutureAdvisorSamlToken")

	@RequestMapping(value = "/{faId}/{yodleeId}", method = RequestMethod.GET, produces = "application/hal+json")
	public Resource<SamlTokenApiResponse> generateSamlToken(@PathVariable("faId") String faId, @PathVariable("yodleeId") String yodleeId,
			 @RequestHeader("Authorization") String authorizationToken, HttpServletRequest request) {

		logger.debug("Entered FutureAdvisorSamlTokenIssuerController.generateSamlToken : faId={}, yodleeId={}", faId, yodleeId);
		
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
			jwtTokenValidator.validateOtherParam(jwtToken, "t_faid", faId);
		}

		/** String token = "<?xml version='1.0' encoding='UTF-8'?><samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:dsig='http://www.w3.org/2000/09/xmldsig#' xmlns:enc='http://www.w3.org/2001/04/xmlenc#' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' xmlns:x500='urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' Destination='https://api.partner-stg.futureadvisor.com/identities/suntrust' ID='id-CVt3-NbLuH4QSVh0mRADwb9cjLay-6sdtwzgIn6o' IssueInstant='2018-09-13T13:41:25Z' Version='2.0'><saml:Issuer Format='urn:oasis:names:tc:SAML:2.0:nameid-format:entity'>https://dev_federation.suntrust.com</saml:Issuer><samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success' /></samlp:Status><saml:Assertion ID='id-eQr6m1-Rzo-QrsWSiTqOhwGVOdyCcr2-fjIrKOag' IssueInstant='2018-09-13T13:41:25Z' Version='2.0'><saml:Issuer Format='urn:oasis:names:tc:SAML:2.0:nameid-format:entity'>https://dev_federation.suntrust.com</saml:Issuer><dsig:Signature><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#' /><dsig:SignatureMethod Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1' /><dsig:Reference URI='#id-eQr6m1-Rzo-QrsWSiTqOhwGVOdyCcr2-fjIrKOag'><dsig:Transforms><dsig:Transform Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature' /><dsig:Transform Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#' /></dsig:Transforms><dsig:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1' /><dsig:DigestValue>6NfEeZE/Lx1QijLOGLivtA+2gR8=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>SlzdMNIYlpKaIBDtlG5UhuWlKjvbcPId+LTb6x/65YplYfqSnasjSoUJrfUIqjpUnLTNstOXDsH2LIo63zFjGZlDGJJ4qx8f1r4CTGwLynjEaStCzrbhOUXh4pPU2MwGNp3Vr3SAjP0k2EOrz77BoR4DRT0vksu1bzsLwvInYvLDUbhikol1depAxaO6+WA23kkcDX7WeisJ/3lA1ZGIzmqKlANROPEGiDo+j0IKLKkdOOk942ItCx9WNGPQ8KRs3twiVUN/Ja2moCv9IxJTw5FkjGj461+v/mwVpLJdBrY2l7WhT5QZOjm1LJKDTwpPsWIdtYWiNL3S7E510CQTHg==</dsig:SignatureValue></dsig:Signature><saml:Subject><saml:NameID Format='orafed-custom'>VO1809121647441105</saml:NameID><saml:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'><saml:SubjectConfirmationData NotOnOrAfter='2018-09-13T13:46:25Z' Recipient='https://api.partner-stg.futureadvisor.com/identities/suntrust' /></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore='2018-09-13T13:41:25Z' NotOnOrAfter='2018-09-13T13:46:25Z'><saml:AudienceRestriction><saml:Audience>https://api.partner-stg.futureadvisor.com/identities/suntrust</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant='2018-09-13T13:41:10Z' SessionIndex='id-oGyJjFrmiNcjnm4Yd79sfRYQiG9P9Hn7tOEL-LtX' SessionNotOnOrAfter='2018-09-13T14:26:10Z'><saml:AuthnContext><saml:AuthnContextClassRef>RETAIL_OnlineBanking_RememberMe_ADV2</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name='YodleeId' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'><saml:AttributeValue xmlns:xs='http://www.w3.org/2001/XMLSchema' xsi:type='xs:string'>VO1809121647463392</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>"; **/
		String token = futureAdvisorSamlTokenGenerator.createToken(faId, yodleeId);
		String ssoUrl = futureAdvisorSamlTokenGenerator.getSsoUrl();
		SamlTokenApiResponse samlTokenResponse = new SamlTokenApiResponse(new SamlToken(token, ssoUrl));
		return processSuccessHateoasResponse(samlTokenResponse, faId, yodleeId, authorizationToken, request);
	}

	private Resource<SamlTokenApiResponse> processSuccessHateoasResponse(SamlTokenApiResponse samlTokenResponse,
			String faId, String yodleeId, String authorizationToken, HttpServletRequest request) {

		Link selfLink = linkTo(
				methodOn(FutureAdvisorSamlTokenIssuerController.class).generateSamlToken(faId, yodleeId, authorizationToken, request))
						.withSelfRel();
		return new Resource<>(samlTokenResponse, selfLink);
	}
}
