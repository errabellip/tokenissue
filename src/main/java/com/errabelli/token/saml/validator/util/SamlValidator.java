package com.errabelli.token.saml.validator.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SamlValidator {
	private static final Logger logger = LoggerFactory.getLogger(SamlValidator.class);

	static Credential getVerifyingCredential(String jksPath, String password, String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {

		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		char[] passwordChars = password.toCharArray();
		FileInputStream fis = new FileInputStream(jksPath);
		ks.load(fis, passwordChars);
		fis.close();

		X509Certificate certificate = (X509Certificate) ks.getCertificate(alias);
		BasicX509Credential credential1 = new BasicX509Credential(certificate);
		return credential1;
	}

	static boolean isIssuerCertificatePresentInKeyStore(String jksPath, String password, String alias)
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {

		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		char[] passwordChars = password.toCharArray();
		FileInputStream fis = new FileInputStream(jksPath);
		ks.load(fis, passwordChars);
		fis.close();

		boolean isIssuerCertificatePresent = ks.isCertificateEntry(alias);
		logger.debug("Alias : {} - {} in the keystore", alias, isIssuerCertificatePresent ? "Present":"Not present");
		if (!isIssuerCertificatePresent) {
			logger.error("Issuer certificate with the alias '{}' is not present in the keystore", alias);
		}
		return isIssuerCertificatePresent;
	}

	static boolean verifyAssertion(Assertion assertion, String issuerString, String audienceUrlString, String jksPath, String keystorePassword, String issuerKeyAliasPrefix, boolean timeValidationEnabled) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, SignatureException {
		if (assertion == null) {
			return false;
		}
		logger.debug("Assertion.IssueInstant in SAML Response = {}", assertion.getIssueInstant() != null ? assertion.getIssueInstant(): null);
		if (!verifyIssueInstant(assertion.getIssueInstant()))
			return false;
		logger.debug("Issuer in Assertion = {}", assertion.getIssuer() != null ? assertion.getIssuer().getValue(): null);
		if (!verifyIssuer(assertion.getIssuer(), issuerString, jksPath, keystorePassword, issuerKeyAliasPrefix))
			return false;
		boolean assertionSignatureValidated = false;
		logger.debug("Assertion.Signature in SAML Response = {}", assertion.getSignature());
		assertionSignatureValidated = verifySignature(assertion.getSignature(), issuerString, assertion.getID(), assertion.getSignatureReferenceID(), jksPath, keystorePassword, issuerKeyAliasPrefix);
		logger.debug("Assertion.Subject in SAML Response = {}", assertion.getSubject());
		if (!verifySubjectConfirmation(assertion.getSubject(), timeValidationEnabled))
			return false;
		logger.debug("Assertion.Conditions in SAML Response = {}", assertion.getConditions());
		if (!verifyConditions(assertion.getConditions(), audienceUrlString, timeValidationEnabled))
			return false;
		return assertionSignatureValidated;
	}

	static boolean verifyIssueInstant(DateTime issueInstant) {
		if (issueInstant == null || issueInstant.isAfterNow()) {
			logger.error("IssueInstant verification failed");
			return false;
		} else {
			return true;
		}
	}

	static boolean verifyStatus(Status status) {
		if (status != null && status.getStatusCode() != null
				&& StatusCode.SUCCESS.equalsIgnoreCase(status.getStatusCode().getValue())) {
			return true;
		} else {
			logger.error("Status verification failed");
			return false;
		}
	}

	static boolean verifyIssuer(Issuer issuer, String issuerString, String jksPath, String keystorePassword,
			String issuerKeyAliasPrefix)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		if (issuer != null && issuerString != null && issuerString.equalsIgnoreCase(issuer.getValue())
				&& isIssuerCertificatePresentInKeyStore(jksPath, keystorePassword,
						issuerKeyAliasPrefix + issuerString)) {
			return true;
		} else {
			logger.error("Issuer verification failed");
			return false;
		}
	}

	static boolean verifyDestination(String destination) {
		if (destination == null /*|| destination.toLowerCase().contains(".suntrust.com")*/
				|| destination.toLowerCase().contains("suntrust")) {
			return true;
		} else {
			logger.error("Destination verification failed");
			return false;
		}
	}

	static boolean verifySignature(Signature signature, String issuerString, String id, String signatureId, String jksPath, String keystorePassword, String issuerKeyAliasPrefix) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, SignatureException {
		logger.debug("Signature verification begins: signature={}; issuer={}; id={}; signatureId={}", signature, issuerString, id, signatureId);
		if (signature == null || issuerString == null) {
			return false;
		}

		if (id == null || signatureId == null || !id.equalsIgnoreCase(signatureId)) {
			return false;
		}

		Credential cred = getVerifyingCredential(jksPath, keystorePassword,
				issuerKeyAliasPrefix + issuerString);
		logger.debug("Signature Verification: Cred = {}", cred);
		SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();

		profileValidator.validate(signature);
		logger.debug("Signature profile validated");
		SignatureValidator.validate(signature, cred);
		logger.debug("Signature validated");
		logger.debug("Signature verified: signature={}; issuer={}; id={}; signatureId={}", signature, issuerString, id, signatureId);
		return true;
	}

	static boolean verifySubjectConfirmation(Subject subject, boolean timeValidationEnabled) {
		if (subject == null) {
			logger.error("SubjectConfirmation element is not available in the SAML Assertion");
			return false;
		}
		if (timeValidationEnabled) {
			SubjectConfirmation subConfirm = subject.getSubjectConfirmations() != null
					? subject.getSubjectConfirmations().get(0) : null;
			DateTime notOnOrAfterTime = subConfirm.getSubjectConfirmationData() != null
					? subConfirm.getSubjectConfirmationData().getNotOnOrAfter() : null;
			if (notOnOrAfterTime == null || notOnOrAfterTime.isBeforeNow()) {
				logger.error("SAML Assertion - SubjectConfirmationData - NotOnOrAfter time validation failed");
				return false;
			}
			DateTime notBeforeTime = subConfirm.getSubjectConfirmationData() != null
					? subConfirm.getSubjectConfirmationData().getNotBefore() : null;
			if (notBeforeTime != null && notBeforeTime.isAfterNow()) {
				logger.error("SAML Assertion - SubjectConfirmationData - NotBefore time validation failed");
				return false;
			}
		}
		return true;
	}

	static boolean verifyConditions(Conditions cond, String audienceUrlString, boolean timeValidationEnabled) {
		if (cond == null) {
			logger.error("SAML Assertion - Conditions element is not available in the SAML Assertion");
			return false;
		}
		AudienceRestriction audRestrict = cond.getAudienceRestrictions() != null? cond.getAudienceRestrictions().get(0) : null;
		if (audRestrict ==  null) {
			logger.error("SAML Assertion - Conditions - AudienceRestriction element is not available in the SAML Assertion");
			return false;
		}
		List<Audience> audiences = audRestrict.getAudiences();
		boolean audienceUrlVerified = false;
		for (Audience aud : audiences) {
			if(audienceUrlString.equalsIgnoreCase(aud.getAudienceURI())){
				audienceUrlVerified = true;
				break;
			}
		}
		if(!audienceUrlVerified) {
			logger.error("SAML Assertion - Conditions - Audience Url verification failed");
			return false;
		}
		if (timeValidationEnabled) {
			DateTime notOnOrAfterTime = cond.getNotOnOrAfter();
			if (notOnOrAfterTime == null || notOnOrAfterTime.isBeforeNow()) {
				logger.error("SAML Assertion - Conditions - NotOnOrAfter time validation failed");
				return false;
			}
			DateTime notBeforeTime = cond.getNotBefore();
			if (notBeforeTime == null || notBeforeTime.isAfterNow()) {
				logger.error("SAML Assertion - Conditions - NotBefore time validation failed");
				return false;
			}
		}
		return true;
	}
}
