package com.errabelli.token.saml.ir.util;

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
import org.opensaml.saml.saml2.core.Condition;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import com.errabelli.token.saml.beans.SamlAttribute;

public class SamlAssertionBuilder {

	private SamlAssertionBuilder() {

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
		return "_" + UUID.randomUUID().toString();
	}

	public static Assertion buildAssertion(List<SamlAttribute> attributes, String issuer, String recipientURL,
			String nameId, Integer expirationTime, String jksPath, String password, String keyPassword, String alias)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException,
			SecurityException, IOException {

		Assertion assertion = buildSAMLObject(Assertion.class, Assertion.DEFAULT_ELEMENT_NAME);
		assertion.setID(randomSAMLId());
		assertion.setIssueInstant(new DateTime().minusMinutes(1));
		assertion.setVersion(SAMLVersion.VERSION_20);

		Signature signature = buildSignature(jksPath, password, keyPassword, alias);
		assertion.setSignature(signature);

		assertion.setIssuer(buildIssuer(issuer));
		assertion.setSubject(buildSubject(nameId, recipientURL, expirationTime));
		assertion.setConditions(buildConditions(recipientURL, expirationTime));
		for (SamlAttribute attribute : attributes) {
			assertion.getAttributeStatements().add(buildAttributeStatement(attribute));
		}

		return assertion;
	}

	private static Issuer buildIssuer(String issuingEntityName) {
		Issuer issuer = buildSAMLObject(Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(issuingEntityName);
		return issuer;
	}

	private static Subject buildSubject(String subjectNameId, String recipient, Integer expirationTime) {

		NameID nameID = buildSAMLObject(NameID.class, NameID.DEFAULT_ELEMENT_NAME);
		nameID.setValue(subjectNameId);
		nameID.setFormat(NameID.UNSPECIFIED);

		SubjectConfirmation subjectConfirmation = buildSAMLObject(SubjectConfirmation.class,
				SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

		Subject subject = buildSAMLObject(Subject.class, Subject.DEFAULT_ELEMENT_NAME);
		subject.setNameID(nameID);
		subject.getSubjectConfirmations().add(subjectConfirmation);

		return subject;
	}

	private static Conditions buildConditions(String uri, Integer expirationTime) {

		Audience audience = buildSAMLObject(Audience.class, Audience.DEFAULT_ELEMENT_NAME);
		audience.setAudienceURI(uri);

		AudienceRestriction audienceRestriction = buildSAMLObject(AudienceRestriction.class,
				AudienceRestriction.DEFAULT_ELEMENT_NAME);
		audienceRestriction.getAudiences().add(audience);

		List<Condition> conditionList = Arrays.asList(audienceRestriction);

		Conditions conditions = buildSAMLObject(Conditions.class, Conditions.DEFAULT_ELEMENT_NAME);

		DateTime now = new DateTime();
//		DateTime currentTime = now.minusMinutes(5);
		conditions.setNotBefore(now);
		if (expirationTime == null) {
			expirationTime = Integer.valueOf(15);
		}
		conditions.setNotOnOrAfter(now.plusMinutes(expirationTime.intValue()));
		conditions.getConditions().addAll(conditionList);

		return conditions;
	}

	private static AttributeStatement buildAttributeStatement(SamlAttribute attribute) {

		AttributeStatement attributeStatement = buildSAMLObject(AttributeStatement.class,
				AttributeStatement.DEFAULT_ELEMENT_NAME);
		attributeStatement.getAttributes().add(buildAttribute(attribute.getName(), attribute.getValues()));
		return attributeStatement;
	}

	private static Attribute buildAttribute(String name, List<String> values) {
		XSStringBuilder stringBuilder = (XSStringBuilder) builderFactory.getBuilder(XSString.TYPE_NAME);

		Attribute attribute = buildSAMLObject(Attribute.class, Attribute.DEFAULT_ELEMENT_NAME);
		attribute.setName(name);
		List<XSString> xsStringList = new ArrayList<>();
		for (String value : values) {
			XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
			stringValue.setValue(value);
			xsStringList.add(stringValue);
		}

		attribute.getAttributeValues().addAll(xsStringList);
		return attribute;
	}

	private static Signature buildSignature(String jksPath, String password, String keyPassword, String alias)
			throws SecurityException, KeyStoreException, NoSuchAlgorithmException, CertificateException,
			UnrecoverableEntryException, IOException {
		Signature signature = buildSAMLObject(Signature.class, Signature.DEFAULT_ELEMENT_NAME);

		Credential credential = getSigningCredential(jksPath, password, keyPassword, alias);
		signature.setSigningCredential(credential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

		X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
		keyInfoGeneratorFactory.setEmitEntityCertificate(true);
		KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
		signature.setKeyInfo(keyInfoGenerator.generate(credential));

		return signature;
	}

	private static Credential getSigningCredential(String jksPath, String password, String keyPassword, String alias)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			UnrecoverableEntryException {

		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		char[] passwordChars = password.toCharArray();
		FileInputStream fis = new FileInputStream(jksPath);
		ks.load(fis, passwordChars);
		fis.close();
		char[] keypwd = keyPassword.toCharArray();
		KeyStore.PrivateKeyEntry prvKeyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
				new KeyStore.PasswordProtection(keypwd));
		PrivateKey prvKey = prvKeyEntry.getPrivateKey();
		X509Certificate certificate = (X509Certificate) prvKeyEntry.getCertificate();
		BasicX509Credential credential = new BasicX509Credential(certificate, prvKey);
		credential.setUsageType(UsageType.SIGNING);
		return credential;
	}

	public static String writeToString(Node node) throws TransformerException {
		TransformerFactory transFactory = TransformerFactory.newInstance();
		Transformer transformer = transFactory.newTransformer();
		StringWriter buffer = new StringWriter();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		transformer.setOutputProperty(OutputKeys.INDENT, "no");
		transformer.transform(new DOMSource(node), new StreamResult(buffer));
		return buffer.toString();
	}

	// Added for Suntrust Sunview portal Saml Changes
	public static Element signResponse(Assertion signableXMLObject, Signature signature)
			throws MarshallingException, SignatureException {

		Element responseElement = getSAMLMarshaller(AssertionMarshaller.class, Assertion.DEFAULT_ELEMENT_NAME)
				.marshall(signableXMLObject);
		Signer.signObject(signature);
		return responseElement;
	}

}
