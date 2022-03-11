package com.errabelli.token.saml.mortgage.util;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.annotation.PostConstruct;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;

import com.errabelli.api.exception.BusinessException;
import com.errabelli.token.saml.beans.SamlAttribute;
import com.errabelli.token.service.constants.SamlTokenConstants;

public class MortgageSamlTokenGenerator {

	private static final Logger logger = LoggerFactory.getLogger(MortgageSamlTokenGenerator.class);

	@Value("${token.saml.mortgage.postUrl}")
	private String ssoUrl;

	@Value("${token.saml.mortgage.audienceUrl}")
	private String audienceUrl;
	
	@Value("${token.saml.mortgage.issuer}")
	private String issuer;

	@Value("${token.saml.mortgage.expirationTime}")
	private Integer expirationTime;

	@Value("${token.saml.mortgage.authnStatementExpirationTime}")
	private Integer authnStatementExpirationTime;

	@Value("${token.saml.mortgage.encryption.enabled}")
	private boolean encryptionEnabled;

	private String jksPath;
	private String keystorePassword;
	private String keystoreAlias;
	private String keystoreSpCertAlias;
	private String pkeyPassword;

	public MortgageSamlTokenGenerator(String jksPath, String keystorePassword, String keystoreAlias, String pkeyPassword, String keystoreSpCertAlias) {
		super();
		this.jksPath = jksPath;
		this.keystorePassword = keystorePassword;
		this.keystoreAlias = keystoreAlias;
		this.pkeyPassword = pkeyPassword;
		this.keystoreSpCertAlias = keystoreSpCertAlias;
	}

	@PostConstruct
	public void initializeSamlService() {
		try {
		InitializationService.initialize();
		} catch (InitializationException ie) {
			throw new BusinessException("SAML initialization failed", "SAML initialization failed", HttpStatus.INTERNAL_SERVER_ERROR, ie);
		}
	}

	public String createToken(String nameId, String email, String last4SSN, String clientNumber, String accessID, String loanNumber,
			String siteID) {
		String issuer = this.issuer;
    	String recipientUrl = this.ssoUrl;
    	String audienceUrl = this.audienceUrl;
    	SamlAttribute attr1 = new SamlAttribute(SamlTokenConstants.ATTR_EMAIL, Arrays.asList(email));
    	SamlAttribute attr2 = new SamlAttribute(SamlTokenConstants.ATTR_LAST_4_SSN, Arrays.asList(last4SSN));
    	SamlAttribute attr3 = new SamlAttribute(SamlTokenConstants.ATTR_CLIENT_NUMBER, Arrays.asList(clientNumber));
    	SamlAttribute attr4 = new SamlAttribute(SamlTokenConstants.ATTR_ACCESS_ID, Arrays.asList(accessID));
    	SamlAttribute attr5 = new SamlAttribute(SamlTokenConstants.ATTR_LOAN_NUMBER, Arrays.asList(loanNumber));
    	SamlAttribute attr6 = new SamlAttribute(SamlTokenConstants.ATTR_SITE_ID, Arrays.asList(siteID));
    	List<SamlAttribute> attributes = Arrays.asList(attr1, attr2, attr3, attr4, attr5, attr6);
    	String token = null;
    	try {
    		token = MortgageSamlBuilder.buildSAMLResponse(attributes, issuer, recipientUrl, audienceUrl, nameId, expirationTime, authnStatementExpirationTime, jksPath, keystorePassword, keystoreAlias, pkeyPassword, keystoreSpCertAlias, encryptionEnabled);
    	} catch (Exception e) {
    		throw new BusinessException("Error building SAML token", "Error building SAML token", HttpStatus.INTERNAL_SERVER_ERROR, e);
    	}
    	logger.debug("SAML Token generated: {}",token);
    	token = Base64.getEncoder().encodeToString(token.getBytes(StandardCharsets.UTF_8));
    	return token;
	}

	public String getSsoUrl() {
		return ssoUrl;
	}

}
