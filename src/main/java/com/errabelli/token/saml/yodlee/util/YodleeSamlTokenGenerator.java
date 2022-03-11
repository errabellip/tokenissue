package com.errabelli.token.saml.yodlee.util;

import java.util.Arrays;
import java.util.List;

import javax.annotation.PostConstruct;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;

import com.errabelli.api.exception.BusinessException;
import com.suntrust.token.saml.beans.SamlAttribute;
import com.suntrust.token.service.constants.SamlTokenConstants;

public class YodleeSamlTokenGenerator {

	private static final Logger logger = LoggerFactory.getLogger(YodleeSamlTokenGenerator.class);

	@Value("${token.saml.Yodlee.postURL}")
	private String yodleeReceipientURL;

	@Value("${token.saml.Yodlee.audienceUrl}")
	private String audienceUrl;

	@Value("${token.saml.Yodlee.expirationTime}")
	private Integer expirationTime;

	private String jksPath;
	private String keystorePassword;
	private String keystoreAlias;

	public YodleeSamlTokenGenerator(String jksPath, String keystorePassword, String keystoreAlias) {
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
			throw new BusinessException("Yodlee SAML initialization failed", "Yodlee SAML initialization failed",
					HttpStatus.INTERNAL_SERVER_ERROR, ie);
		}
	}

	public String createToken(String nameId, String yodleeAttribute) {
		String issuer = SamlTokenConstants.YODLEE_ISSUER;
		SamlAttribute attr1 = null;
		List<SamlAttribute> attributes = null;
		if (yodleeAttribute != null) {
			attr1 = new SamlAttribute(SamlTokenConstants.YODLEE_ATTR, Arrays.asList(yodleeAttribute));
			attributes = Arrays.asList(attr1);
		}
		String token = null;
		try {
			token = YodleeSamlBuilder.buildYodleeSAMLResponse(attributes, issuer, yodleeReceipientURL, nameId,
					expirationTime, jksPath, keystorePassword, keystoreAlias, audienceUrl);
		} catch (Exception e) {
			throw new BusinessException("Error building SAML token", "Error building SAML token",
					HttpStatus.INTERNAL_SERVER_ERROR, e);
		}
		logger.debug("Yodlee SAML Token generated: {}", token);
		return token;
	}

}
