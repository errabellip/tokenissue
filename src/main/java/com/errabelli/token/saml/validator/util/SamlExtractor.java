package com.errabelli.token.saml.validator.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSAnyImpl;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import com.errabelli.api.exception.BusinessException;
import com.errabelli.token.saml.validator.beans.SamlResponseAttribute;
import com.errabelli.token.saml.validator.beans.SamlResponseExtract;

public class SamlExtractor {
	private static final Logger logger = LoggerFactory.getLogger(SamlExtractor.class);

	private static final UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport
			.getUnmarshallerFactory();

	@Value("${token.saml.validator.timeValidation.enabled}")
	private boolean timeValidationEnabled;

	@Value("${token.saml.validator.audienceUrl}")
	private String audienceUrl;

	private String jksPath;
	private String keystorePassword;
	private String issuerKeyAliasPrefix;

	public SamlExtractor(String jksPath, String keystorePassword, String issuerKeyAliasPrefix) {
		super();
		this.jksPath = jksPath;
		this.keystorePassword = keystorePassword;
		this.issuerKeyAliasPrefix = issuerKeyAliasPrefix;
	}

	public SamlResponseExtract processSamlResponse(String samlResponse, String issuerString) {

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder docBuilder = null;
		try {
			docBuilder = documentBuilderFactory.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			throw new BusinessException("SAML validation failure", "SAML validation failure", HttpStatus.INTERNAL_SERVER_ERROR);
		}

		// Base64 decode the SAML response string and convert it into a SAML Response object
		String samlResponseString = new String(Base64.getDecoder().decode(samlResponse));
		logger.debug("SAML Response = {}", samlResponseString);
		Document document = null;
		try {
			document = docBuilder.parse(new ByteArrayInputStream(samlResponseString.getBytes()));
		} catch (SAXException | IOException e) {
			throw new BusinessException("SAML Response parsing failure", "SAML Response parsing failure", HttpStatus.BAD_REQUEST);
		}
		Element element = document.getDocumentElement();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
		XMLObject responseXmlObj = null;
		try {
			responseXmlObj = unmarshaller.unmarshall(element);
		} catch (UnmarshallingException e) {
			throw new BusinessException("SAML Response parsing failure", "SAML Response parsing failure", HttpStatus.BAD_REQUEST);
		}
		Response response = (Response) responseXmlObj;

		// Response validation
		if (response == null) {
			throw new BusinessException("SAML validation failure", "SAML validation failure", HttpStatus.BAD_REQUEST);
		}

		// Verify response level elements and attributes
		// Response element – Verify that IssueInstant attribute value is in the past
		logger.debug("Response.IssueInstant in SAML Response = {}", response.getIssueInstant() != null ? response.getIssueInstant(): null);
		if (!SamlValidator.verifyIssueInstant(response.getIssueInstant())) {
			throw new BusinessException("SAML validation failure", "SAML validation failure", HttpStatus.BAD_REQUEST);
		}

		// Response.StatusCode – Verify that it is a success status
		logger.debug("Response.Status in SAML Response = {}", (response.getStatus() != null && response.getStatus().getStatusCode() != null) ? response.getStatus().getStatusCode().getValue(): null);
		if (!SamlValidator.verifyStatus(response.getStatus())) {
			throw new BusinessException("SAML validation failure", "SAML validation failure", HttpStatus.BAD_REQUEST);
		}

		// Verify that the issuer in SAML matches the issuer in request
		logger.debug("Issuer in SAML Response = {}", response.getIssuer() != null ? response.getIssuer().getValue(): null);
		try {
			if (!SamlValidator.verifyIssuer(response.getIssuer(), issuerString, jksPath, keystorePassword, issuerKeyAliasPrefix)) {
				throw new BusinessException("SAML validation failure", "SAML validation failure", HttpStatus.BAD_REQUEST);
			}
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			throw new BusinessException("SAML validation failure", "SAML validation failure",
					HttpStatus.INTERNAL_SERVER_ERROR);
		}

		// Response element - Verify that destination is a "suntrust.com" url
		logger.debug("Destination in SAML Response = {}", response.getDestination());
		if (!SamlValidator.verifyDestination(response.getDestination())) {
			throw new BusinessException("SAML validation failure", "SAML validation failure", HttpStatus.BAD_REQUEST);
		}

		// Response.Signature - Validate the signature on the SAML response
		// Verify that ID attribute value in Response element matches the reference URI of the signature with an addition of ‘#’ at the beginning
		boolean signatureValidated = false, assertionSignatureValidated = false;
		logger.debug("Response.Signature in SAML Response = {}", response.getSignature() != null ? response.getSignature(): null);

		if (response.getSignature() != null) {
			try {
				if (SamlValidator.verifySignature(response.getSignature(), issuerString, response.getID(),
						response.getSignatureReferenceID(), jksPath, keystorePassword, issuerKeyAliasPrefix)) {
					signatureValidated = true;
				} else {
					logger.error("Response signature validation failed");
					throw new BusinessException("SAML validation failure", "SAML validation failure",
							HttpStatus.BAD_REQUEST);
				}
			} catch (SignatureException e) {
				logger.error("Response signature validation failed with exception - ", e);
				throw new BusinessException("SAML validation failure", "SAML validation failure",
						HttpStatus.BAD_REQUEST);
			} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
				logger.error("Response signature validation failed with exception - ", e);
				throw new BusinessException("SAML validation failure", "SAML validation failure",
						HttpStatus.INTERNAL_SERVER_ERROR);
			}
		}

		// Extract assertion
		if (response.getEncryptedAssertions() != null && response.getEncryptedAssertions().size() > 0) {
			// TODO: Implement in future to support encryption assertions
		} else if (response.getAssertions() != null && response.getAssertions().size() > 0) {
			logger.debug("Assertion in SAML Response = {}", response.getAssertions().get(0) != null ? response.getAssertions().get(0): null);
			try {
				if (SamlValidator.verifyAssertion(response.getAssertions().get(0), issuerString, audienceUrl, jksPath, keystorePassword, issuerKeyAliasPrefix, timeValidationEnabled)) {
					assertionSignatureValidated = true;
				} else {
					logger.warn("Assertion verification failed");
				}
			} catch (SignatureException e) {
				logger.error("Assertion signature validation failed with exception - ", e);
				throw new BusinessException("SAML validation failure", "SAML validation failure", HttpStatus.BAD_REQUEST);
			} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException  e) {
				logger.error("Assertion signature validation failed with exception - ", e);
				throw new BusinessException("SAML validation failure", "SAML validation failure", HttpStatus.INTERNAL_SERVER_ERROR);
			}
		} else {
			logger.error("Assertion missing in the SAML");
			throw new BusinessException("SAML validation failure", "SAML validation failure", HttpStatus.BAD_REQUEST);
		}

		// Either Response or Assertion must be signed
		if (!signatureValidated && !assertionSignatureValidated) {
			logger.error("Response or Assertion Signature validation failed");
			throw new BusinessException("SAML validation failure", "SAML validation failure", HttpStatus.BAD_REQUEST);
		}

		// Extract assertion attributes
		String nameID = null, recipient = null, audience = null;
		List<SamlResponseAttribute> attributes = new ArrayList<SamlResponseAttribute>();
		if (response.getEncryptedAssertions() != null && response.getEncryptedAssertions().size() > 0) {
			// TODO: Implement in future to support encryption assertions
		} else if (response.getAssertions() != null && response.getAssertions().size() > 0) {
			logger.debug("Assertion in SAML Response = {}",
					response.getAssertions().get(0) != null ? response.getAssertions().get(0) : null);
			Assertion assertion = response.getAssertions().get(0);
			nameID = extractNameID(assertion);
			logger.debug("NameID = {}", nameID);
			recipient = extractRecipient(assertion);
			logger.debug("Recipient = {}", recipient);
			audience = extractAudience(assertion);
			logger.debug("Audience = {}", audience);
			extractAttributes(assertion, attributes);
			logger.debug("Attributes = {}", attributes);

		}
		return new SamlResponseExtract(nameID, recipient, audience, attributes);
	}

	private String extractNameID(Assertion assertion) {
		String nameID = null;
		if (assertion != null && assertion.getSubject() != null
				&& assertion.getSubject().getNameID() != null)
			nameID = assertion.getSubject().getNameID().getValue();
		return nameID;
	}

	private String extractRecipient(Assertion assertion) {
		String recipient = null;
		if (assertion != null && assertion.getSubject() != null
				&& assertion.getSubject().getSubjectConfirmations() != null
				&& assertion.getSubject().getSubjectConfirmations().size() > 0
				&& assertion.getSubject().getSubjectConfirmations().get(0) != null
				&& assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData() != null)
			recipient = assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().getRecipient();
		return recipient;
	}

	private String extractAudience(Assertion assertion) {
		String audience = null;
		if (assertion != null && assertion.getConditions() != null
				&& assertion.getConditions().getAudienceRestrictions() != null
				&& assertion.getConditions().getAudienceRestrictions().size() > 0
				&& assertion.getConditions().getAudienceRestrictions().get(0) != null
				&& assertion.getConditions().getAudienceRestrictions().get(0).getAudiences() != null
				&& assertion.getConditions().getAudienceRestrictions().get(0).getAudiences().size() > 0
				&& assertion.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0) != null)
			audience = assertion.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).getAudienceURI();
		return audience;
	}

	private void extractAttributes(Assertion assertion, List<SamlResponseAttribute> attributes) {
		if (assertion != null && assertion.getAttributeStatements() != null) {
			for (AttributeStatement statement : assertion.getAttributeStatements()) {
				if (statement != null && statement.getAttributes() != null && statement.getAttributes().size() > 0) {
					for (Attribute attribute : statement.getAttributes()) {
						if (attribute != null) {
							List<XMLObject> attributeValues = attribute.getAttributeValues();
			                if (!attributeValues.isEmpty())
			                {
			                    attributes.add(new SamlResponseAttribute(attribute.getName(), getAttributeValue(attributeValues.get(0))));
			                }
						}
					}
				}
			}
		}
	}

	private String getAttributeValue(XMLObject attributeValue)
	{
	    return attributeValue == null ?
	            null :
	            attributeValue instanceof XSString ?
	                    getStringAttributeValue((XSString) attributeValue) :
	                    attributeValue instanceof XSAnyImpl ?
	                            getAnyAttributeValue((XSAnyImpl) attributeValue) :
	                            attributeValue.toString();
	}

	private String getStringAttributeValue(XSString attributeValue)
	{
	    return attributeValue.getValue();
	}

	private String getAnyAttributeValue(XSAnyImpl attributeValue)
	{
	    return attributeValue.getTextContent();
	}
}
