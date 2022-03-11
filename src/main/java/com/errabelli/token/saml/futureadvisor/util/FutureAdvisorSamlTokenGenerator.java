package com.errabelli.token.saml.futureadvisor.util;

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

public class FutureAdvisorSamlTokenGenerator {

	private static final Logger logger = LoggerFactory.getLogger(FutureAdvisorSamlTokenGenerator.class);
	
	@Value("${token.saml.futureadvisor.postUrl}")
	private String ssoUrl;
	
	@Value("${token.saml.futureadvisor.audienceUrl}")
	private String audienceUrl;
	
	@Value("${token.saml.futureadvisor.issuer}")
	private String issuer;

	@Value("${token.saml.futureadvisor.expirationTime}")
	private Integer expirationTime;

	@Value("${token.saml.futureadvisor.authnStatementExpirationTime}")
	private Integer authnStatementExpirationTime;

	private String jksPath;
	private String keystorePassword;
	private String keystoreAlias;
	private String pkeyPassword;

	public FutureAdvisorSamlTokenGenerator(String jksPath, String keystorePassword, String keystoreAlias, String pkeyPassword) {
		super();
		this.jksPath = jksPath;
		this.keystorePassword = keystorePassword;
		this.keystoreAlias = keystoreAlias;
		this.pkeyPassword = pkeyPassword;
	}

	@PostConstruct
	public void initializeSamlService() {
		try {
		InitializationService.initialize();
		} catch (InitializationException ie) {
			throw new BusinessException("SAML initialization failed", "SAML initialization failed", HttpStatus.INTERNAL_SERVER_ERROR, ie);
		}
	}

	public String createToken(String nameId, String applicationName) {
		String issuer = this.issuer;
    	String recipientUrl = this.ssoUrl;
    	String audienceUrl = this.audienceUrl;
    	SamlAttribute attr1 = new SamlAttribute(SamlTokenConstants.ATTR_YODLEE_ID, Arrays.asList(applicationName));
    	List<SamlAttribute> attributes = Arrays.asList(attr1);
    	String token = null;
    	try {
    		token = FutureAdvisorSamlBuilder.buildSAMLResponse(attributes, issuer, recipientUrl, audienceUrl, nameId, expirationTime, authnStatementExpirationTime, jksPath, keystorePassword, keystoreAlias, pkeyPassword);
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
