package com.errabelli.token.saml.sunviewula.sso.util;

import java.io.IOException;
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
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;

import com.errabelli.api.exception.BusinessException;
import com.errabelli.token.saml.beans.SamlAttribute;
import com.errabelli.token.saml.ir.beans.SamlAssertionResponse;

public class OLCUlaSSOSamlGenerator {

	private static final Logger logger = LoggerFactory.getLogger(OLCUlaSSOSamlGenerator.class);

	@Value("${token.saml.svp.ula.olc.issuer}")
	private String svpUlaSSOIssuer;

	@Value("${token.saml.olc.sso.expirationTime}")
	private Integer expirationTime;

	@Value("${token.saml.olc.sso.postURL}")
	private String olcReceipientURL;

	@Value("${token.saml.olc.sso.recipient}")
	private String olcAudienceURL;

	private String jksPath;
	private String keystorePassword;
	private String keystoreAlias;
	private String keyPassword;

	public OLCUlaSSOSamlGenerator(String jksPath, String keystorePassword, String keystoreAlias, String keyPassword) {
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

	public SamlAssertionResponse createSamlResponse(String userGuid, String olcAttributeName,
			String olcAttributeValue) {
		String assertionString = null;
		String nameId = userGuid;
		SamlAttribute attr1 = null;
		attr1 = new SamlAttribute(olcAttributeName, Arrays.asList(olcAttributeValue));
		List<SamlAttribute> attributes = Arrays.asList(attr1);

		String response = null;
		try {
			response = OLCUlaSSOSamlBuilder.buildSAMLResponse(attributes, svpUlaSSOIssuer, olcReceipientURL, nameId,
					expirationTime, jksPath, keystorePassword, keystoreAlias, keyPassword, olcAudienceURL);

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
