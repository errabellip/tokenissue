package com.errabelli.token.saml.wealthscape.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import javax.xml.namespace.QName;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Condition;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.saml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.saml2.encryption.Encrypter.KeyPlacement;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import com.errabelli.token.saml.beans.SamlAttribute;

public class WealthscapeSamlBuilder {
	
	private WealthscapeSamlBuilder(){
		
	}

	private static final XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

	private static final MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();

	@SuppressWarnings({ "unchecked" })
	public static <T> T buildSAMLObject(final Class<T> objectClass, QName qName) {
		return (T) builderFactory.getBuilder(qName).buildObject(qName);
	}

	@SuppressWarnings({ "unchecked" })
	public static <T> T getSAMLMarshaller(final Class<T> objectClass, QName qName) {
		return (T) marshallerFactory.getMarshaller(qName);
	}

	private static String randomSAMLId() {
		return "id-" + UUID.randomUUID().toString();
	}

	public static String buildSAMLResponse(List<SamlAttribute> attributes, String issuer, String recipientURL, String audienceURL, String nameId, Integer expirationTime, Integer authnStatementExpirationTime, String jksPath, String password, String alias, String keyPassword, String spCertAlias, boolean encryptionEnabled) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException, SecurityException, IOException, TransformerException, MarshallingException, SignatureException, InitializationException, EncryptionException {

		Response response = buildSAMLObject(Response.class, Response.DEFAULT_ELEMENT_NAME);
		DateTime now = new DateTime();

		response.setVersion(SAMLVersion.VERSION_20);
		response.setID(randomSAMLId());
		response.setIssueInstant(now);
		response.setDestination(recipientURL);
		response.setStatus(buildSuccessStatus());
		response.setIssuer(buildIssuer(issuer));

		Assertion assertion = buildAssertion(attributes, issuer, recipientURL, audienceURL, nameId, expirationTime, authnStatementExpirationTime, now);
		Signature signature1 = buildSignature(jksPath, password, alias, keyPassword);
		assertion.setSignature(signature1);
		signAssertion(assertion, signature1);

		if (encryptionEnabled) {
			// Encrypt the assertion (This is a signed and encrypted assertion)
			EncryptedAssertion encryptedAssertion = encrypt(assertion, jksPath, password, spCertAlias);
			response.getEncryptedAssertions().add(encryptedAssertion);
		} else {
			// This block returns response with assertion without encryption
			response.getAssertions().add(assertion);
		}

		Signature signature2 = buildSignature(jksPath, password, alias, keyPassword);
		response.setSignature(signature2);
		return writeToString(signResponse(response, signature2));
	}

	public static Status buildSuccessStatus() {

		StatusCode statusCode = buildSAMLObject(StatusCode.class, StatusCode.DEFAULT_ELEMENT_NAME);
		statusCode.setValue(StatusCode.SUCCESS);

		Status status = buildSAMLObject(Status.class, Status.DEFAULT_ELEMENT_NAME);
		status.setStatusCode(statusCode);
		return status;
	}

	public static Assertion buildAssertion(List<SamlAttribute> attributes, String issuer, String recipientURL, String audienceURL, String nameId, Integer expirationTime, Integer authnStatementExpirationTime, DateTime now) {

		Assertion assertion = buildSAMLObject(Assertion.class, Assertion.DEFAULT_ELEMENT_NAME);
		assertion.setID(randomSAMLId());
		assertion.setIssueInstant(now);
		assertion.setVersion(SAMLVersion.VERSION_20);

		assertion.setIssuer(buildIssuer(issuer));
		assertion.setSubject(buildSubject(nameId, recipientURL, expirationTime, now));
		assertion.setConditions(buildConditions(audienceURL, expirationTime, now));
		assertion.getAuthnStatements().add(buildAuthnStatement(authnStatementExpirationTime, now));
		for (SamlAttribute attribute: attributes) {
			assertion.getAttributeStatements().add(buildAttributeStatement(attribute));
		}

		return assertion;
	}

	private static Element signAssertion(Assertion signableXMLObject, Signature signature) throws MarshallingException, SignatureException {

		Element assertionElement = getSAMLMarshaller(AssertionMarshaller.class, Assertion.DEFAULT_ELEMENT_NAME).marshall(signableXMLObject);
		Signer.signObject(signature);
		return assertionElement;
	}

	private static Element signResponse(Response signableXMLObject, Signature signature) throws MarshallingException, SignatureException {

		Element responseElement = getSAMLMarshaller(ResponseMarshaller.class, Response.DEFAULT_ELEMENT_NAME).marshall(signableXMLObject);
		Signer.signObject(signature);
		return responseElement;
	}

	private static Issuer buildIssuer(String issuingEntityName) {
		Issuer issuer = buildSAMLObject(Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(issuingEntityName);
		issuer.setFormat(NameIDType.ENTITY);
		return issuer;
	}

	private static Subject buildSubject(String subjectNameId, String recipient, Integer expirationTime, DateTime now) {

		NameID nameID = buildSAMLObject(NameID.class, NameID.DEFAULT_ELEMENT_NAME);
		nameID.setValue(subjectNameId);
		nameID.setFormat("orafed-custom");

		SubjectConfirmationData subjectConfirmationData = buildSAMLObject(SubjectConfirmationData.class, SubjectConfirmationData.DEFAULT_ELEMENT_NAME);

		//subjectConfirmationData.setNotBefore(now);
		if (expirationTime == null)
			expirationTime = Integer.valueOf(15);
		subjectConfirmationData.setNotOnOrAfter(now.plusMinutes(expirationTime.intValue()));
		subjectConfirmationData.setRecipient(recipient);

		SubjectConfirmation subjectConfirmation = buildSAMLObject(SubjectConfirmation.class, SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
		subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

		Subject subject = buildSAMLObject(Subject.class, Subject.DEFAULT_ELEMENT_NAME);
		subject.setNameID(nameID);
		subject.getSubjectConfirmations().add(subjectConfirmation);

		return subject;
	}

	private static Conditions buildConditions(String uri, Integer expirationTime, DateTime now) {

		Audience audience = buildSAMLObject(Audience.class, Audience.DEFAULT_ELEMENT_NAME);
		audience.setAudienceURI(uri);

		AudienceRestriction audienceRestriction = buildSAMLObject(AudienceRestriction.class, AudienceRestriction.DEFAULT_ELEMENT_NAME);
		audienceRestriction.getAudiences().add(audience);

		// Create the do-not-cache condition
		//Condition oneTimeUseCondition = buildSAMLObject(OneTimeUse.class, OneTimeUse.DEFAULT_ELEMENT_NAME);

		//List<Condition> conditionList = Arrays.asList(audienceRestriction, oneTimeUseCondition);
		List<Condition> conditionList = Arrays.asList(audienceRestriction);

		Conditions conditions = buildSAMLObject(Conditions.class, Conditions.DEFAULT_ELEMENT_NAME);

		conditions.setNotBefore(now);
		if (expirationTime == null)
			expirationTime = Integer.valueOf(15);
		conditions.setNotOnOrAfter(now.plusMinutes(expirationTime.intValue()));
		conditions.getConditions().addAll(conditionList);

		return conditions;
	}

	private static AuthnStatement buildAuthnStatement(Integer authnStatementExpirationTime, DateTime now) {
		AuthnContextClassRef authnContextClassRef = buildSAMLObject(AuthnContextClassRef.class, AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		//authnContextClassRef.setAuthnContextClassRef(AuthnContext.UNSPECIFIED_AUTHN_CTX);
		authnContextClassRef.setAuthnContextClassRef("RETAIL_OnlineBanking_RememberMe");

		AuthnContext authnContext = buildSAMLObject(AuthnContext.class, AuthnContext.DEFAULT_ELEMENT_NAME);
		authnContext.setAuthnContextClassRef(authnContextClassRef);

		AuthnStatement authnStatement = buildSAMLObject(AuthnStatement.class, AuthnStatement.DEFAULT_ELEMENT_NAME);
		authnStatement.setAuthnContext(authnContext);

		authnStatement.setAuthnInstant(now);
		if (authnStatementExpirationTime == null)
			authnStatementExpirationTime = Integer.valueOf(60);
		authnStatement.setSessionNotOnOrAfter(now.plusMinutes(authnStatementExpirationTime));

		authnStatement.setSessionIndex(randomSAMLId());
		return authnStatement;
	}

	private static AttributeStatement buildAttributeStatement(SamlAttribute attribute) {

		AttributeStatement attributeStatement = buildSAMLObject(AttributeStatement.class, AttributeStatement.DEFAULT_ELEMENT_NAME);
		attributeStatement.getAttributes().add(buildAttribute(attribute.getName(), attribute.getValues()));
		return attributeStatement;
	}

	private static Attribute buildAttribute(String name, List<String> values) {
		XSStringBuilder stringBuilder = (XSStringBuilder) builderFactory.getBuilder(XSString.TYPE_NAME);

		Attribute attribute = buildSAMLObject(Attribute.class, Attribute.DEFAULT_ELEMENT_NAME);
		attribute.setName(name);

		List<XSString> xsStringList = new ArrayList<>();
		for (String value: values) {
			XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
			stringValue.setValue(value);
			xsStringList.add(stringValue);
		}

		attribute.getAttributeValues().addAll(xsStringList);
		return attribute;
	}

	private static Signature buildSignature(String jksPath, String password, String alias, String keyPassword) throws SecurityException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException, IOException {
		Signature signature = buildSAMLObject(Signature.class, Signature.DEFAULT_ELEMENT_NAME);

		Credential credential = getSigningCredential(jksPath, password, alias, keyPassword);
		signature.setSigningCredential(credential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

		// Commenting out Key Info section - Public Cert info will not be added to signature
		//X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
		//keyInfoGeneratorFactory.setEmitEntityCertificate(true);
		//KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
		//signature.setKeyInfo(keyInfoGenerator.generate(credential));

		return signature;
	}

	private static Credential getSigningCredential(String jksPath, String password, String alias, String keyPassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException {

		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		char[] passwordChars = password.toCharArray();
		FileInputStream fis = new FileInputStream(jksPath);
		ks.load(fis, passwordChars);
		fis.close();

		char[] keyPasswordChars = keyPassword.toCharArray();
		KeyStore.PrivateKeyEntry prvKeyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection(keyPasswordChars));
		PrivateKey prvKey = prvKeyEntry.getPrivateKey();
		X509Certificate certificate = (X509Certificate) prvKeyEntry.getCertificate();
		BasicX509Credential credential = new BasicX509Credential(certificate, prvKey);
		credential.setUsageType(UsageType.SIGNING);
		return credential;
	}

	public static String writeToString(Node node) throws TransformerException{
		TransformerFactory transFactory = TransformerFactory.newInstance();
		Transformer transformer = transFactory.newTransformer();
		StringWriter buffer = new StringWriter();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
		transformer.setOutputProperty(OutputKeys.INDENT, "no");
		transformer.transform(new DOMSource(node), new StreamResult(buffer));
		return buffer.toString();
	}

	private static EncryptedAssertion encrypt(Assertion assertion, String jksPath, String password, String alias) throws InitializationException, EncryptionException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		Credential keyEncryptionCredential = getEncryptionCredential(jksPath, password, alias);

		DataEncryptionParameters encParams = new DataEncryptionParameters();
		encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);

		KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
		kekParams.setEncryptionCredential(keyEncryptionCredential);
		kekParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15);
		KeyInfoGeneratorFactory kigf = DefaultSecurityConfigurationBootstrap.buildDefaultEncryptionConfiguration().getDataKeyInfoGeneratorManager().getFactory(alias, keyEncryptionCredential);
		kekParams.setKeyInfoGenerator(kigf.newInstance());

		Encrypter samlEncrypter = new Encrypter(encParams, kekParams);
		samlEncrypter.setKeyPlacement(KeyPlacement.PEER);

		EncryptedAssertion encryptedAssertion = samlEncrypter.encrypt(assertion);
		return encryptedAssertion;
	}

	private static Credential getEncryptionCredential(String jksPath, String password, String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		char[] passwordChars = password.toCharArray();
		FileInputStream fis = new FileInputStream(jksPath);
		ks.load(fis, passwordChars);
		fis.close();

		X509Certificate certificate = (X509Certificate) ks.getCertificate(alias);
		BasicX509Credential credential = new BasicX509Credential(certificate);
		credential.setUsageType(UsageType.ENCRYPTION);
		return credential;
	}
}
