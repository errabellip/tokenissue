package com.errabelli.token.saml.yodlee.util;

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
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Condition;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.OneTimeUse;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.impl.ResponseMarshaller;
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

import com.suntrust.token.saml.beans.SamlAttribute;

public class YodleeSamlBuilder {

	private YodleeSamlBuilder() {

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

	public static String buildYodleeSAMLResponse(List<SamlAttribute> attributes, String issuer, String recipientURL,
			String nameId, Integer expirationTime, String jksPath, String password, String alias, String audienceUrl)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException,
			SecurityException, IOException, TransformerException, MarshallingException, SignatureException {

		Response response = buildSAMLObject(Response.class, Response.DEFAULT_ELEMENT_NAME);

		response.setConsent(randomSAMLId());
		response.setDestination(recipientURL);
		response.setID(randomSAMLId());
		response.setIssueInstant(new DateTime());
		response.setVersion(SAMLVersion.VERSION_20);
		response.setStatus(buildSuccessStatus());
		response.setIssuer(buildIssuer(issuer));

		response.getAssertions()
				.add(buildAssertion(attributes, issuer, recipientURL, nameId, expirationTime, audienceUrl));
		Signature signature = buildSignature(jksPath, password, alias);
		response.setSignature(signature);
		return writeToString(signResponse(response, signature));
	}

	public static Assertion buildAssertion(List<SamlAttribute> attributes, String issuer, String recipientURL,
			String nameId, Integer expirationTime, String audienceUrl) {

		Assertion assertion = buildSAMLObject(Assertion.class, Assertion.DEFAULT_ELEMENT_NAME);

		assertion.setID(randomSAMLId());
		assertion.setIssueInstant(new DateTime());
		assertion.setVersion(SAMLVersion.VERSION_20);

		assertion.setIssuer(buildIssuer(issuer));
		assertion.setSubject(buildSubject(nameId, recipientURL, expirationTime));
		assertion.setConditions(buildConditions(audienceUrl, expirationTime));
		assertion.getAuthnStatements().add(buildAuthnStatement());
		if (attributes != null) {
			for (SamlAttribute attribute : attributes) {
				assertion.getAttributeStatements().add(buildAttributeStatement(attribute));
			}
		}

		return assertion;
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

	private static AuthnStatement buildAuthnStatement() {
		AuthnContextClassRef authnContextClassRef = buildSAMLObject(AuthnContextClassRef.class,
				AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		authnContextClassRef.setAuthnContextClassRef(AuthnContext.UNSPECIFIED_AUTHN_CTX);

		AuthnContext authnContext = buildSAMLObject(AuthnContext.class, AuthnContext.DEFAULT_ELEMENT_NAME);
		authnContext.setAuthnContextClassRef(authnContextClassRef);

		AuthnStatement authnStatement = buildSAMLObject(AuthnStatement.class, AuthnStatement.DEFAULT_ELEMENT_NAME);
		authnStatement.setAuthnContext(authnContext);
		authnStatement.setAuthnInstant(new DateTime());
		System.out.println(new DateTime());
		String sessionIndex = "YODTEST- " + new DateTime();
		authnStatement.setSessionIndex(sessionIndex);

		return authnStatement;
	}

	private static Conditions buildConditions(String uri, Integer expirationTime) {

		Audience audience = buildSAMLObject(Audience.class, Audience.DEFAULT_ELEMENT_NAME);
		audience.setAudienceURI(uri);

		AudienceRestriction audienceRestriction = buildSAMLObject(AudienceRestriction.class,
				AudienceRestriction.DEFAULT_ELEMENT_NAME);
		audienceRestriction.getAudiences().add(audience);

		// Create the do-not-cache condition
		Condition oneTimeUseCondition = buildSAMLObject(OneTimeUse.class, OneTimeUse.DEFAULT_ELEMENT_NAME);

		List<Condition> conditionList = Arrays.asList(audienceRestriction, oneTimeUseCondition);

		Conditions conditions = buildSAMLObject(Conditions.class, Conditions.DEFAULT_ELEMENT_NAME);

		DateTime now = new DateTime();
		conditions.setNotBefore(now);
		if (expirationTime == null)
			expirationTime = Integer.valueOf(15);
		conditions.setNotOnOrAfter(now.plusMinutes(expirationTime.intValue()));
		conditions.getConditions().addAll(conditionList);

		return conditions;
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

	public static Status buildSuccessStatus() {

		StatusCode statusCode = buildSAMLObject(StatusCode.class, StatusCode.DEFAULT_ELEMENT_NAME);
		statusCode.setValue(StatusCode.SUCCESS);

		Status status = buildSAMLObject(Status.class, Status.DEFAULT_ELEMENT_NAME);
		status.setStatusCode(statusCode);
		return status;
	}

	private static Issuer buildIssuer(String issuingEntityName) {
		Issuer issuer = buildSAMLObject(Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(issuingEntityName);
		return issuer;
	}

	private static Element signResponse(Response signableXMLObject, Signature signature)
			throws MarshallingException, SignatureException {

		Element responseElement = getSAMLMarshaller(ResponseMarshaller.class, Response.DEFAULT_ELEMENT_NAME)
				.marshall(signableXMLObject);
		Signer.signObject(signature);
		return responseElement;
	}

	private static Signature buildSignature(String jksPath, String password, String alias)
			throws SecurityException, KeyStoreException, NoSuchAlgorithmException, CertificateException,
			UnrecoverableEntryException, IOException {
		Signature signature = buildSAMLObject(Signature.class, Signature.DEFAULT_ELEMENT_NAME);

		Credential credential = getSigningCredential(jksPath, password, alias);
		signature.setSigningCredential(credential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_OMIT_COMMENTS);

		X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
		keyInfoGeneratorFactory.setEmitEntityCertificate(true);
		KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
		signature.setKeyInfo(keyInfoGenerator.generate(credential));

		return signature;
	}

	private static Credential getSigningCredential(String jksPath, String password, String alias)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
			UnrecoverableEntryException {

		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		char[] passwordChars = password.toCharArray();
		FileInputStream fis = new FileInputStream(jksPath);
		ks.load(fis, passwordChars);
		fis.close();
		
		KeyStore.PrivateKeyEntry prvKeyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection(passwordChars));
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
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
		transformer.setOutputProperty(OutputKeys.INDENT, "no");
		transformer.transform(new DOMSource(node), new StreamResult(buffer));
		return buffer.toString();
	}

}
