package com.errabelli.token.saml.pietech.util;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.annotation.PostConstruct;

import org.apache.commons.lang3.StringUtils;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;

import com.errabelli.api.exception.BusinessException;
import com.errabelli.token.saml.beans.SamlAttribute;
import com.errabelli.token.service.constants.SamlTokenConstants;

public class SamlTokenGenerator {

	private static final Logger logger = LoggerFactory.getLogger(SamlTokenGenerator.class);
	
	private static final String[] ENTITLEMENTS_PWM = new String[] { "STFPWMCLIENT" };
	private static final String[] ENTITLEMENTS_NOT_GUEST = new String[] { "STFBRANCH", "STFADVISOR" };

	@Value("${token.saml.pietech.postUrl}")
	private String clientMgpURL;

	@Value("${token.saml.pietech.pwmPostUrl}")
	private String pwmMgpURL;

	@Value("${token.saml.expirationTime}")
	private Integer expirationTime;

	private String jksPath;
	private String keystorePassword;
	private String keystoreAlias;

	public SamlTokenGenerator(String jksPath, String keystorePassword, String keystoreAlias) {
		super();
		this.jksPath = jksPath;
		this.keystorePassword = keystorePassword;
		this.keystoreAlias = keystoreAlias;
	}

	@PostConstruct
	public void initializeSamlService() {
		try {
		InitializationService.initialize();
		} catch (InitializationException ie) {
			throw new BusinessException("SAML initialization failed", "SAML initialization failed", HttpStatus.INTERNAL_SERVER_ERROR, ie);
		}
	}

	public String createToken(String guestId, String planId, String entitlements) {
		String issuer = SamlTokenConstants.ISSUER;
    	String recipientURL = this.getMgpURL(entitlements);
    	String guestFlag = this.getGuestFromEntitlements(entitlements);
    	String nameId = planId;
    	SamlAttribute attr1 = new SamlAttribute(SamlTokenConstants.ATTR_GUEST_ID, Arrays.asList(guestId));
    	SamlAttribute attr2 = new SamlAttribute(SamlTokenConstants.ATTR_HOUSEHOLD_ID, Arrays.asList(planId));
    	SamlAttribute attr3 = new SamlAttribute(SamlTokenConstants.ATTR_ENTITLEMENTS, Arrays.asList(entitlements));
    	SamlAttribute attr4 = new SamlAttribute(SamlTokenConstants.ATTR_IS_GUEST, Arrays.asList(guestFlag));
    	List<SamlAttribute> attributes = Arrays.asList(attr1, attr2, attr3, attr4);
    	String token = null;
    	try {
    		token = SamlBuilder.buildSAMLResponse(attributes, issuer, recipientURL, nameId, expirationTime, jksPath, keystorePassword, keystoreAlias);
    	} catch (Exception e) {
    		throw new BusinessException("Error building SAML token", "Error building SAML token", HttpStatus.INTERNAL_SERVER_ERROR, e);
    	}
    	logger.debug("SAML Token generated: {}",token);
    	token = Base64.getEncoder().encodeToString(token.getBytes(StandardCharsets.UTF_8));
    	return token;
	}

	public String getMgpURL(String entitlements) {
		String mgpURL = clientMgpURL;
		entitlements = entitlements.trim().toUpperCase();
		if (StringUtils.startsWithAny(entitlements, ENTITLEMENTS_PWM))
			mgpURL = pwmMgpURL;
		return mgpURL;
	}

	private String getGuestFromEntitlements(String entitlements) {
		String isGuest = "Yes";
		entitlements = entitlements.trim().toUpperCase();
		if (StringUtils.startsWithAny(entitlements, ENTITLEMENTS_NOT_GUEST))
			isGuest = "No";
		return isGuest;
	}
}
