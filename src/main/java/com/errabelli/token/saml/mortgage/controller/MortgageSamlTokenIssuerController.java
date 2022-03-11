package com.suntrust.token.saml.mortgage.controller;

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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.errabelli.api.exception.BusinessException;
import com.errabelli.token.saml.beans.SamlToken;
import com.errabelli.token.saml.beans.SamlTokenApiResponse;
import com.errabelli.token.saml.mortgage.util.MortgageSamlTokenGenerator;
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
@RequestMapping("/saml/mortgage/${token.saml.mortgage.api.version}")
public class MortgageSamlTokenIssuerController {

	private static final String REFERER = "Referer";

	@Autowired
	MortgageSamlTokenGenerator mortgageSamlTokenGenerator;

	@Autowired
	private JwtTokenValidator jwtTokenValidator;

	private static final Logger logger = LoggerFactory.getLogger(MortgageSamlTokenIssuerController.class);

	@ApiOperation(value = "GET SAML Token for Mortgage", notes = "This service provides SAML token to be used to post to Mortgage", nickname = "GetMortgageSamlToken")

	@RequestMapping(value = "/{guid}/{accessID}", method = RequestMethod.GET, produces = "application/hal+json")
	public Resource<SamlTokenApiResponse> generateSamlToken(@PathVariable("guid") String guid, @PathVariable("accessID") String accessID,
			@RequestParam(value = "email", required = false) String email,
			@RequestParam(value = "last4SSN", required = false) String last4SSN,
			@RequestParam(value = "clientNumber", required = false) String clientNumber,
			@RequestParam(value = "loanNumber", required = false) String loanNumber,
			@RequestParam(value = "siteID", required = false) String siteID,
			@RequestHeader("Authorization") String authorizationToken, HttpServletRequest request) {

		logger.debug("Entered MortgageSamlTokenIssuerController.generateSamlToken :guid = {}, accessID = {}", guid, accessID);
		logger.debug(
				"Entered MortgageSamlTokenIssuerController.generateSamlToken :email = {}, last4SSN = {}, clientNumber = {}, loanNumber = {}, siteID = {}",
				email, last4SSN, clientNumber, loanNumber, siteID);
		
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
			jwtTokenValidator.validateOtherParam(jwtToken, "tuserguid", guid, "AECIN", accessID);
		}

		/**String token_encrypted = "<?xml version='1.0' encoding='UTF-8'?><samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:dsig='http://www.w3.org/2000/09/xmldsig#' xmlns:enc='http://www.w3.org/2001/04/xmlenc#' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' xmlns:x500='urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' Destination='https://mysuntrustmortgage.uat.customercarenet.com/ccn/stm/ssoservlet' ID='id--5pgCSEoth4rs0GOsDkkuIL3OZV3kMWWNsKup9Qi' IssueInstant='2018-09-23T17:13:44Z' Version='2.0'><saml:Issuer Format='urn:oasis:names:tc:SAML:2.0:nameid-format:entity'>https://itca_federation.suntrust.com</saml:Issuer><samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success' /></samlp:Status><saml20:EncryptedAssertion xmlns:saml20='urn:oasis:names:tc:SAML:2.0:assertion'><xenc:EncryptedData xmlns:xenc='http://www.w3.org/2001/04/xmlenc#' Id='id-PG-AvnSgvsjzp1Sm-vQiRFSVZKoJC488ULwGoMA6' Type='http://www.w3.org/2001/04/xmlenc#Element'><xenc:EncryptionMethod Algorithm='http://www.w3.org/2001/04/xmlenc#aes128-cbc' /><KeyInfo xmlns='http://www.w3.org/2000/09/xmldsig#'><dsig:RetrievalMethod Type='http://www.w3.org/2001/04/xmlenc#EncryptedKey' URI='#id-lHhSHBtkLzm9qW2RCOMV3X2-e5Mpz-jR-zeGdFcU' /></KeyInfo><xenc:CipherData><xenc:CipherValue>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</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData><xenc:EncryptedKey xmlns:xenc='http://www.w3.org/2001/04/xmlenc#' Id='id-lHhSHBtkLzm9qW2RCOMV3X2-e5Mpz-jR-zeGdFcU'><xenc:EncryptionMethod Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-1_5' /><dsig:KeyInfo><dsig:X509Data><dsig:X509Certificate>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</dsig:X509Certificate></dsig:X509Data></dsig:KeyInfo><xenc:CipherData><xenc:CipherValue>OpMjNl7aKoDikKvMlVJ0fR7W/ka89mz0GLFut1EYdwkHNT3/QsKzIu5r67uxzy9acTO344wBd8OVjJ9hmjuBOQnCkEbuj09E5RdcIzpzS5R4BJFJKeeZZvSQtxQJ76Q5EORNhESxskBtGIWIQHoKV8GEcfRFYuFiX6CkhLYwoipRiZVK9rGkgU4+qTaTXmyrdKNDOgtC97Px7qthYCLF+4gAMG2OugyoRX8PDzWVlNinzccWUd1nQ/AIBRAFLPWzTvZuomU6KRO4oC8GJDlS2+HUCAAM+Dt7MU+F6infUXtj3g0FM55UU6YA/wZhFoutXEc497iGTvUKSDQ8sa3r8w==</xenc:CipherValue></xenc:CipherData><xenc:ReferenceList><xenc:DataReference URI='#id-PG-AvnSgvsjzp1Sm-vQiRFSVZKoJC488ULwGoMA6' /></xenc:ReferenceList></xenc:EncryptedKey></saml20:EncryptedAssertion></samlp:Response>"; **/
		/**String token_decrypted = "<?xml version='1.0' encoding='UTF-8'?><samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:dsig='http://www.w3.org/2000/09/xmldsig#' xmlns:enc='http://www.w3.org/2001/04/xmlenc#' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' xmlns:x500='urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' Destination='https://mysuntrustmortgage.uat.customercarenet.com/ccn/stm/ssoservlet' ID='id-Wv6ZWpK45SVCM25L3CGGf6tnBNN7Ty0oSUoXcFAu' IssueInstant='2018-09-23T17:17:27Z' Version='2.0'><saml:Issuer Format='urn:oasis:names:tc:SAML:2.0:nameid-format:entity'>https://itca_federation.suntrust.com</saml:Issuer><samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success' /></samlp:Status><saml:Assertion ID='id-wpd-DKv3-VKou6R3llxFr67HJzBnoMVEhUu5REoL' IssueInstant='2018-09-23T17:17:27Z' Version='2.0'><saml:Issuer Format='urn:oasis:names:tc:SAML:2.0:nameid-format:entity'>https://itca_federation.suntrust.com</saml:Issuer><dsig:Signature><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#' /><dsig:SignatureMethod Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1' /><dsig:Reference URI='#id-wpd-DKv3-VKou6R3llxFr67HJzBnoMVEhUu5REoL'><dsig:Transforms><dsig:Transform Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature' /><dsig:Transform Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#' /></dsig:Transforms><dsig:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1' /><dsig:DigestValue>t3fOUwFPLum3jNQqjQ8k/Q6Un+4=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>VVu512nBRRmcdE+/Zu9LqYC7JLFWdfoZR4AxgoqSx2/NkuaRY5/RxpNWftFhfF2zAi7cKGoqVFFF9wz8ejHgIZVecsqOheEAMDTHcQ+QugyJnzb2pPUXTS2BmwQW18xbJv64JnxC3eBKO1GCBWsmyjKOTbJT2y9S9Ow6y+VifrL0kkJvIdjktsqVYrvXCZfvs/1Ci7XNb6WbKOH70wtQw+A7uR/9FxEZWuoFpfJnJd2SuGp3kF5zcr33TAhUF/pphL+5dZ7eClmWPEFH36yYJ1l1akQjVbC5/0yswiSV1OqCjFg6/xvGmQWv247ramH/b23oL9aTNeJNOzhc0ymd7w==</dsig:SignatureValue></dsig:Signature><saml:Subject><saml:NameID Format='orafed-custom'>abfe7b0c-a2f1-4fae-bd45-0a5489aad7ea</saml:NameID><saml:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'><saml:SubjectConfirmationData NotOnOrAfter='2018-09-23T17:22:27Z' Recipient='https://mysuntrustmortgage.uat.customercarenet.com/ccn/stm/ssoservlet' /></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore='2018-09-23T17:17:27Z' NotOnOrAfter='2018-09-23T17:22:27Z'><saml:AudienceRestriction><saml:Audience>ccn_sp</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant='2018-09-23T17:13:13Z' SessionIndex='id-GpypwhAeL5dwjhIkO273cuA8M2DkFvk-JZv0wYqE' SessionNotOnOrAfter='2018-09-23T18:17:27Z'><saml:AuthnContext><saml:AuthnContextClassRef>RETAIL_OnlineBanking_RememberMe</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name='Email' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'><saml:AttributeValue xsi:nil='true' /></saml:Attribute><saml:Attribute Name='Last4SSN' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'><saml:AttributeValue xsi:nil='true' /></saml:Attribute><saml:Attribute Name='ClientNumber' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'><saml:AttributeValue xmlns:xs='http://www.w3.org/2001/XMLSchema' xsi:type='xs:string'>942</saml:AttributeValue></saml:Attribute><saml:Attribute Name='AccessID' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'><saml:AttributeValue xmlns:xs='http://www.w3.org/2001/XMLSchema' xsi:type='xs:string'>217562718</saml:AttributeValue></saml:Attribute><saml:Attribute Name='LoanNumber' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'><saml:AttributeValue xsi:nil='true' /></saml:Attribute><saml:Attribute Name='SiteID' NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic'><saml:AttributeValue xmlns:xs='http://www.w3.org/2001/XMLSchema' xsi:type='xs:string'>VO</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>"; **/
		String token = mortgageSamlTokenGenerator.createToken(guid, email, last4SSN, clientNumber, accessID, loanNumber, siteID);
		String ssoUrl = mortgageSamlTokenGenerator.getSsoUrl();
		SamlTokenApiResponse samlTokenResponse = new SamlTokenApiResponse(new SamlToken(token, ssoUrl));
		return processSuccessHateoasResponse(samlTokenResponse, guid, accessID, email, last4SSN, clientNumber,
				loanNumber, siteID, authorizationToken, request);
	}

	private Resource<SamlTokenApiResponse> processSuccessHateoasResponse(SamlTokenApiResponse samlTokenResponse,
			String nameId, String accessID, String email, String last4SSN, String clientNumber, String loanNumber,
			String siteID, String authorizationToken, HttpServletRequest request) {

		Link selfLink = linkTo(methodOn(MortgageSamlTokenIssuerController.class).generateSamlToken(nameId, accessID, email,
				last4SSN, clientNumber, loanNumber, siteID, authorizationToken, request)).withSelfRel();
		return new Resource<>(samlTokenResponse, selfLink);
	}
}
