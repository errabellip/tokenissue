package com.errabelli.token.saml.sunviewula.sso.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Base64;

import javax.annotation.PostConstruct;
import javax.xml.transform.TransformerException;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;

import com.errabelli.api.exception.BusinessException;
import com.errabelli.token.saml.ir.beans.SamlAssertionResponse;

public class IPUlaSSOSamlGenerator {

	private static final Logger logger = LoggerFactory.getLogger(IPUlaSSOSamlGenerator.class);

	@Value("${token.saml.ip.sso.expirationTime}")
	private Integer expirationTime;

	@Value("${token.saml.svp.ula.ip.issuer}")
	private String svpUlaSSOIssuer;

	@Value("${token.saml.ip.sso.postURL}")
	private String ipReceipientURL;

	@Value("${token.saml.ip.sso.recipient}")
	private String ipAudienceURL;

	private String jksPath;
	private String keystorePassword;
	private String keystoreAlias;
	private String keyPassword;

	public IPUlaSSOSamlGenerator(String jksPath, String keystorePassword, String keystoreAlias, String keyPassword) {
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

	public SamlAssertionResponse createSamlResponse(String userGuid) {

		String assertionString = null;
		String nameId = userGuid;
		String response = null;
		try {

			response = IPUlaSSOSamlBuilder.buildSAMLResponse(svpUlaSSOIssuer, ipReceipientURL, ipAudienceURL, nameId,
					expirationTime, jksPath, keystorePassword, keystoreAlias, keyPassword);

			logger.debug("Assertion: {}", response);
			assertionString = new String(Base64.getEncoder().encode(response.getBytes(StandardCharsets.UTF_8)),
					"UTF-8");
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
