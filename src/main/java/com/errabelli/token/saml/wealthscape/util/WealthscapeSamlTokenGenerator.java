package com.errabelli.token.saml.wealthscape.util;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
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

public class WealthscapeSamlTokenGenerator {

	private static final Logger logger = LoggerFactory.getLogger(WealthscapeSamlTokenGenerator.class);

	@Value("${token.saml.wealthscape.postUrl}")
	private String ssoUrl;

	@Value("${token.saml.wealthscape.audienceUrl}")
	private String audienceUrl;
	
	@Value("${token.saml.wealthscape.issuer}")
	private String issuer;

	@Value("${token.saml.wealthscape.expirationTime}")
	private Integer expirationTime;

	@Value("${token.saml.wealthscape.authnStatementExpirationTime}")
	private Integer authnStatementExpirationTime;

	@Value("${token.saml.wealthscape.encryption.enabled}")
	private boolean encryptionEnabled;

	private String jksPath;
	private String keystorePassword;
	private String keystoreAlias;
	private String pkeyPassword;
	private String keystoreSpCertAlias;

	public WealthscapeSamlTokenGenerator(String jksPath, String keystorePassword, String keystoreAlias, String pkeyPassword, String keystoreSpCertAlias) {
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

	public String createToken(String nameId) {
		String issuer = this.issuer;
    	String recipientUrl = this.ssoUrl;
    	String audienceUrl = this.audienceUrl;
    	List<SamlAttribute> attributes = new ArrayList<SamlAttribute>();
    	String token = null;
    	try {
    		token = WealthscapeSamlBuilder.buildSAMLResponse(attributes, issuer, recipientUrl, audienceUrl, nameId, expirationTime, authnStatementExpirationTime, jksPath, keystorePassword, keystoreAlias, pkeyPassword, keystoreSpCertAlias, encryptionEnabled);
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
