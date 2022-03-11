package com.errabelli.token.saml.ir.util;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.xml.transform.TransformerException;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;

import com.errabelli.api.exception.BusinessException;
import com.errabelli.token.saml.beans.SamlAttribute;
import com.errabelli.token.saml.ir.beans.SamlAssertionResponse;
import com.errabelli.token.service.constants.SamlTokenConstants;

public class SamlAssertionGenerator {

	private static final Logger logger = LoggerFactory.getLogger(SamlAssertionGenerator.class);

	@Value("${token.saml.IR.postURL}")
	private String irReceipientURL;

	@Value("${token.saml.expirationTime}")
	private Integer expirationTime;

	@Value("${token.saml.IR.issuer}")
	private String irIssuer;

	private String jksPath;
	private String keystorePassword;
	private String keystoreAlias;
	private String keyPassword;

	public SamlAssertionGenerator(String jksPath, String keystorePassword, String keystoreAlias, String keyPassword) {
		super();
		this.jksPath = jksPath;
		this.keystorePassword = keystorePassword;
		this.keystoreAlias = keystoreAlias;
		this.keyPassword = keyPassword;
	}

	@PostConstruct
	public void initializeSamlService() {
		try {
			InitializationService.initialize();
		} catch (InitializationException ie) {
			throw new BusinessException("SAML initialization failed", "SAML initialization failed",
					HttpStatus.INTERNAL_SERVER_ERROR, ie);
		}
	}

	public SamlAssertionResponse createSamlAssertion(String entity, String userName) {
		String assertionString = null;
		String nameId = SamlTokenConstants.SAML_IR_NAME_ID;
		SamlAttribute attr1 = new SamlAttribute(SamlTokenConstants.SAML_IR_SSO_ATTRIBUTE,
				Arrays.asList(entity.concat("|").concat(userName)));
		List<SamlAttribute> attributes = Arrays.asList(attr1);
		try {
			Assertion assertion = SamlAssertionBuilder.buildAssertion(attributes, irIssuer, irReceipientURL, nameId,
					expirationTime, jksPath, keystorePassword, keyPassword, keystoreAlias);

			assertionString = SamlAssertionBuilder
					.writeToString(SamlAssertionBuilder.signResponse(assertion, assertion.getSignature()));

			logger.debug("Assertion: {}", assertionString);
			assertionString = URLEncoder.encode(
					new String(Base64.getEncoder().encode(assertionString.getBytes(StandardCharsets.UTF_8))), "UTF-8");
		} catch (MarshallingException | SignatureException | KeyStoreException | NoSuchAlgorithmException
				| CertificateException | UnrecoverableEntryException | SecurityException | IOException
				| TransformerException e) {
			logger.error("Error generating SAML Assertion", e);
			throw new BusinessException("Error building SAML Assertion", "Error building SAML Assertion",
					HttpStatus.INTERNAL_SERVER_ERROR, e);
		}
		return new SamlAssertionResponse(assertionString);
	}
}
