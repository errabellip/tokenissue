package com.errabelli.token.saml.wealthscape.controller;

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
import com.errabelli.token.saml.wealthscape.util.WealthscapeSamlTokenGenerator;
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
@RequestMapping("/saml/wealthscape/${token.saml.wealthscape.api.version}")
public class WealthscapeSamlTokenIssuerController {

	private static final String REFERER = "Referer";

	@Autowired
	WealthscapeSamlTokenGenerator wealthscapeSamlTokenGenerator;

	@Autowired
	private JwtTokenValidator jwtTokenValidator;

	private static final Logger logger = LoggerFactory.getLogger(WealthscapeSamlTokenIssuerController.class);

	@ApiOperation(value = "GET SAML Token for Wealthscape", notes = "This service provides SAML token to be used to post to Wealthscape", nickname = "GetWealthscapeSamlToken")

	@RequestMapping(value = "/{investorId}", method = RequestMethod.GET, produces = "application/hal+json")
	public Resource<SamlTokenApiResponse> generateSamlToken(@PathVariable("investorId") String investorId,
			 @RequestHeader("Authorization") String authorizationToken, HttpServletRequest request) {

		logger.debug("Entered WealthscapeSamlTokenIssuerController.generateSamlToken :{}", investorId);
		
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
			jwtTokenValidator.validateOtherParam(jwtToken, "t_investorid", investorId);
		}

		/**String token_encrypted = "<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:dsig='http://www.w3.org/2000/09/xmldsig#' xmlns:enc='http://www.w3.org/2001/04/xmlenc#' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' xmlns:x500='urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' Destination='https://loginxq1.mystreetscape.com/ftgw/Fas/nfExternal/SSCorrClient/InboundSSO/consumer/sp/ACS.saml2' ID='id-xMbh9OdzSCYl9FqCA7ro6WvbFO-yCVRykr5A3vJa' IssueInstant='2018-09-23T03:30:11Z' Version='2.0'><saml:Issuer Format='urn:oasis:names:tc:SAML:2.0:nameid-format:entity'>https://itca_federation.suntrust.com</saml:Issuer><dsig:Signature><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#' /><dsig:SignatureMethod Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1' /><dsig:Reference URI='#id-xMbh9OdzSCYl9FqCA7ro6WvbFO-yCVRykr5A3vJa'><dsig:Transforms><dsig:Transform Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature' /><dsig:Transform Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#' /></dsig:Transforms><dsig:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1' /><dsig:DigestValue>oE/jMTuZx7Hy8/ItpAM3BAGN67A=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>aveUXKDd8tMc1sJALZ1Q0qevf+ebD3bjkx+i9jPne70ICw3veN5Jsj/OqAOwamYq+Xt/BOfg3lrADRk79QutgMBX8vJ+tZgpTuMATwJcOpltMwbgA81Ns665wf9T1ncLju3qFd6VfYpRKPF5xyf6TMF3S0pHb7e+fP2jNBHNP8v2JDXY5rJtoDOc/2V4An9wPnEoimz95C571wX2VCNKWrrGp6HCSSFil16+BymV3ccPVlzj8DUdI/ZaqAbV6ZepFfguqwkV2fHYLW7IS/eYtWHUIUrT7GUbaJVGDZoad6SK7Q0VfVrgB8tzUKBqvRJ46ArdJ69YnwzbJCImf7ZHCQ==</dsig:SignatureValue></dsig:Signature><samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success' /></samlp:Status><saml20:EncryptedAssertion xmlns:saml20='urn:oasis:names:tc:SAML:2.0:assertion'><xenc:EncryptedData xmlns:xenc='http://www.w3.org/2001/04/xmlenc#' Id='id-YqtM9VEztxg66AnEvYzawL6VC1bIHQT-8qtQS1Fq' Type='http://www.w3.org/2001/04/xmlenc#Element'><xenc:EncryptionMethod Algorithm='http://www.w3.org/2001/04/xmlenc#aes128-cbc' /><KeyInfo xmlns='http://www.w3.org/2000/09/xmldsig#'><dsig:RetrievalMethod Type='http://www.w3.org/2001/04/xmlenc#EncryptedKey' URI='#id--TH-COCYI0aUFaDi5J2U1-WgSq-KxhbOkUpn0oSd' /></KeyInfo><xenc:CipherData><xenc:CipherValue>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</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData><xenc:EncryptedKey xmlns:xenc='http://www.w3.org/2001/04/xmlenc#' Id='id--TH-COCYI0aUFaDi5J2U1-WgSq-KxhbOkUpn0oSd'><xenc:EncryptionMethod Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-1_5' /><dsig:KeyInfo><dsig:X509Data><dsig:X509Certificate>MIIFSDCCBDCgAwIBAgINAPWv1QwAAAAAUNbRqTANBgkqhkiG9w0BAQsFADCBujELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUVudHJ1c3QsIEluYy4xKDAmBgNVBAsTH1NlZSB3d3cuZW50cnVzdC5uZXQvbGVnYWwtdGVybXMxOTA3BgNVBAsTMChjKSAyMDEyIEVudHJ1c3QsIEluYy4gLSBmb3IgYXV0aG9yaXplZCB1c2Ugb25seTEuMCwGA1UEAxMlRW50cnVzdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAtIEwxSzAeFw0xNjAxMjUyMjQ3MDBaFw0xOTAzMTgyMzE2NThaMH0xCzAJBgNVBAYTAlVTMRYwFAYDVQQIEw1NYXNzYWNodXNldHRzMQ8wDQYDVQQHEwZCb3N0b24xHTAbBgNVBAoTFEZpZGVsaXR5IEludmVzdG1lbnRzMSYwJAYDVQQDEx1zYW1sc3NvLXhxYS5teXN0cmVldHNjYXBlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM109h65ZYpWW1RhqbRGnHV2GDCi7LKUC8B6xfeKea8XuC2dgEE7OOVTyi+dUL7s4alzxz8ehxdyRBu5N4UlD9N3gXCyknQFJQiXim010p1y1pgZZUhGjw2a0NC8wxQYwhwIxxcUvybwhZ2BYp/CtH6oNMnkhqB2PxvvYXsiwiY0Q0ngnIAL4nfWbXxoHAuBzh04u1bbiYkgcf+8k1XNq9UvTE5/8Bqvbhqpli4jwuz0kpry8ZrX/hUbMXFKwz7LEM7S8zs6ht8ry5O6M80m2n1LWx2P5U/mi951THUMzwMyetMIzcpuoWi6SctoOEwTxYGVkiuO+VXCwGbokKLnDdkCAwEAAaOCAYcwggGDMAsGA1UdDwQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3JsLmVudHJ1c3QubmV0L2xldmVsMWsuY3JsMEsGA1UdIAREMEIwNgYKYIZIAYb6bAoBBTAoMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LmVudHJ1c3QubmV0L3JwYTAIBgZngQwBAgIwaAYIKwYBBQUHAQEEXDBaMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5lbnRydXN0Lm5ldDAzBggrBgEFBQcwAoYnaHR0cDovL2FpYS5lbnRydXN0Lm5ldC9sMWstY2hhaW4yNTYuY2VyMCgGA1UdEQQhMB+CHXNhbWxzc28teHFhLm15c3RyZWV0c2NhcGUuY29tMB8GA1UdIwQYMBaAFIKicHTdvFM/z3vU981/p2DGCky/MB0GA1UdDgQWBBRvGfKh7P7YIaOMk+dnP/A2tVZh6jAJBgNVHRMEAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQBfQZOC+xyzSA8lTMUXhpEUKHcqkcSKzC2MYMAWWU59ssHDZh7HHwAwurHrHWi4ocZKSKu9WoVssBKBR7Dcb1n99LGRXgcikcJc1bc8TD7wgdmXC21PoxM2NAouPB991KzP+voi3nYM1fuECXmTH3cYcpHCtH1ej8sLHmRuQs8TBJoFMEZYvkjjyVM328w/qde/rxdKV65JF7NcIdo11OLd0GvQ6wNHqRVQvc3obMa2774hVBqmXteb2yq9Io8v2+T+63GE0kKgV+l2ezv6J+fK9LIqL9fgFXLtC2RCa7oMdAm9MD9zL2UXKn+kNuTTkWppoF1qWdc0vC7hMOjxXzIl</dsig:X509Certificate></dsig:X509Data></dsig:KeyInfo><xenc:CipherData><xenc:CipherValue>ko1Bx6MYnoYWocKQLkZXXA9tz6Knf9kta/aDfxelhhggMe2w0U7rmv3noXm3GM7Y5AFld1c7hPCB1pmiIIJKjdh1Chmmg6hG+5yj7yomgJ89WXpH46/n9biHW8j9mhcqnehFY4WNS40QzW7cdxc/pQdIJDbYT3PTWijUhsWoiAlvx6SchLjvrtCrac3q84WTdRHlCc1jb/UHSu58yGAd3vh3xcekoMI2EKbj83zAH/q/BUFihUaTyZtxZXpS6B3Ds2u20i0HoMANqh6sWM1pUAYLKAqEta8MCDHluoTlSqhwgBeMsFr+tzaty8jjAGreB1SAET8EZqgDPfyT1o/WHg==</xenc:CipherValue></xenc:CipherData><xenc:ReferenceList><xenc:DataReference URI='#id-YqtM9VEztxg66AnEvYzawL6VC1bIHQT-8qtQS1Fq' /></xenc:ReferenceList></xenc:EncryptedKey></saml20:EncryptedAssertion></samlp:Response>"; **/
		/**String token_decrypted = "<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:dsig='http://www.w3.org/2000/09/xmldsig#' xmlns:enc='http://www.w3.org/2001/04/xmlenc#' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' xmlns:x500='urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' Destination='https://loginxq1.mystreetscape.com/ftgw/Fas/nfExternal/SSCorrClient/InboundSSO/consumer/sp/ACS.saml2' ID='id-cZ9Al77iGToQnA6Yhbjhi11mqJtScdz98Q1d1MRG' IssueInstant='2018-09-23T16:57:24Z' Version='2.0'><saml:Issuer Format='urn:oasis:names:tc:SAML:2.0:nameid-format:entity'>https://itca_federation.suntrust.com</saml:Issuer><dsig:Signature><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#' /><dsig:SignatureMethod Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1' /><dsig:Reference URI='#id-cZ9Al77iGToQnA6Yhbjhi11mqJtScdz98Q1d1MRG'><dsig:Transforms><dsig:Transform Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature' /><dsig:Transform Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#' /></dsig:Transforms><dsig:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1' /><dsig:DigestValue>xQJqW/hQJDmgDev/bJBLiqkeBdE=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>QFzDoKgU+BTRZXrkUJRs9O5sIVlpsjkW6IqmJv3Ituvi6esuDCY4v7iCRcLLyTEzSAeJOgVJkh0eJbR0ks7UIoPhrhhvx/0EoV6wCOis040znEj+J7oKgMiXY0Rfy3M8BUgT3moYmPITBy0I9Rpod8yO1NkliSwFC38siFepTz3As3IOqUpeQ55VHNmPDYXWlbB47VnxPhPoiV4b3M8iqGaffpzXF/PkugOkH1AGXX1ysBPEKBt8ZhVij/HQm41rmpOHV9xsBkOL3nz6oT/zzedhd2Ow3qkgRNSxsXFDTSuSX7Pu8amYXXd6knOUILWJpQbAifRIuc4unTUP3HOJ0A==</dsig:SignatureValue></dsig:Signature><samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success' /></samlp:Status><saml:Assertion ID='id--WehWlB5GvdfEBQCwBQs-311oKzInM09w06uHsI6' IssueInstant='2018-09-23T16:57:24Z' Version='2.0'><saml:Issuer Format='urn:oasis:names:tc:SAML:2.0:nameid-format:entity'>https://itca_federation.suntrust.com</saml:Issuer><dsig:Signature><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#' /><dsig:SignatureMethod Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1' /><dsig:Reference URI='#id--WehWlB5GvdfEBQCwBQs-311oKzInM09w06uHsI6'><dsig:Transforms><dsig:Transform Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature' /><dsig:Transform Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#' /></dsig:Transforms><dsig:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1' /><dsig:DigestValue>C0kmjXgm1ZnDi71ovUVPekxDJy8=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>WFFU7c85vkzDPzJQsWXJeY64jgB9sT/BL8OvL/1J8R9hPHqqcLwPtxBPKWdhNMQ6oCVB4NsZQYoJVJmMbAsnNMRy7gMqakTRnzOhkOAgT+qo7zozaNJPfVIph9f7iWfloE+krPaDWv+qytipP7rJyH3FIcPii4PGz382O/ICIzpOeOgGiqEvU/EAWqFLCIGlukIDIqA82dXNsEB87wQJVvocyGHjA/9Ig/pdDmOt6xa2KDhMQQ9pidEctPHbQk5L3E073B+t4egTMD5n9MWeWVnUgUAVLRyt71ZJ3GsLMOpw0h72y4IFkvSWmu/SsgL38Jeb7F0KmOzJDh/JDVvdwg==</dsig:SignatureValue></dsig:Signature><saml:Subject><saml:NameID Format='orafed-custom'>9865213355</saml:NameID><saml:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'><saml:SubjectConfirmationData NotOnOrAfter='2018-09-23T17:02:24Z' Recipient='https://loginxq1.mystreetscape.com/ftgw/Fas/nfExternal/SSCorrClient/InboundSSO/consumer/sp/ACS.saml2' /></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore='2018-09-23T16:57:24Z' NotOnOrAfter='2018-09-23T17:02:24Z'><saml:AudienceRestriction><saml:Audience>urn:sp:STS:MYSSCorrTest</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant='2018-09-23T16:52:25Z' SessionIndex='id-f4ytJAbrhKOCeYJAH0eW9yLWbi5JLukrA7skEdpB' SessionNotOnOrAfter='2018-09-23T17:57:24Z'><saml:AuthnContext><saml:AuthnContextClassRef>RETAIL_OnlineBanking_RememberMe</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>"; **/
		String token = wealthscapeSamlTokenGenerator.createToken(investorId);
		String ssoUrl = wealthscapeSamlTokenGenerator.getSsoUrl();
		SamlTokenApiResponse samlTokenResponse = new SamlTokenApiResponse(new SamlToken(token, ssoUrl));
		return processSuccessHateoasResponse(samlTokenResponse, investorId, authorizationToken, request);
	}

	private Resource<SamlTokenApiResponse> processSuccessHateoasResponse(SamlTokenApiResponse samlTokenResponse,
			String nameId, String authorizationToken, HttpServletRequest request) {

		Link selfLink = linkTo(
				methodOn(WealthscapeSamlTokenIssuerController.class).generateSamlToken(nameId, authorizationToken, request))
						.withSelfRel();
		return new Resource<>(samlTokenResponse, selfLink);
	}
}
