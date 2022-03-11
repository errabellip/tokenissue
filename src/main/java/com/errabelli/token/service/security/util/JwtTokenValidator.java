package com.errabelli.token.service.security.util;

import java.text.ParseException;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.errabelli.api.exception.CustomSecurityException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;

/**
 * Class validates a given token by using the secret configured in the
 * application
 */
@Component
public class JwtTokenValidator {

	private static final Logger logger = LoggerFactory.getLogger(JwtTokenValidator.class);

	@Value("${jwt.secret}")
	private String secret;

	/**
	 * Tries to parse specified String as a JWT token. If successful, returns
	 * User object with username, id and role prefilled (extracted from token).
	 * If unsuccessful (token is invalid or not containing all required user
	 * properties), simply returns null.
	 *
	 * @param token
	 *            the JWT token to parse
	 * @return the User object extracted from specified token or null if a token
	 *         is invalid.
	 * @throws ParseException
	 * @throws JOSEException
	 */
	public SignedJWT parseToken(String token) throws ParseException, JOSEException {
		logger.debug("parseToken: Start");
		SignedJWT signedJWT = SignedJWT.parse(token);

		JWSVerifier verifier = new MACVerifier(secret.getBytes());
		if (!signedJWT.verify(verifier)) {
			logger.error("JWT Token can't be verified");
			throw new JOSEException("JWT Token can't be verified");
		}
		if (signedJWT.getJWTClaimsSet() != null && isTokenExpired(signedJWT.getJWTClaimsSet().getExpirationTime())) {
			logger.error("JWT Token is expired");
			throw new JOSEException("JWT Token is expired");
		}
		logger.debug("parseToken: Successfully verified");
		return signedJWT;
	}

	public void validateAecinParam(String token, String aecinParam) {

		logger.debug("validateAecinParam: aecinParam = {}", aecinParam);

		try {
			SignedJWT parseToken = parseToken(token);
			if (parseToken.getJWTClaimsSet().getClaim("AECIN") != null) {
				String aecinTokenParam = (String) parseToken.getJWTClaimsSet().getClaim("AECIN");
				logger.debug("validateAecinParam: aecinTokenParam from token == {}", aecinTokenParam);
				if (!aecinParam.equals(aecinTokenParam)) {
					logger.error(
							"Token validation failed: AECIN in the request ({}) does not match AECIN in the token ({})",
							aecinParam, aecinTokenParam);
					throw new CustomSecurityException("validateAecinParam: aecin param not matching");
				}
			} else {
				logger.error("AECIN is not found in the token claims set");
				throw new CustomSecurityException("validateAecinParam: aecin param is not found in the token");
			}
		} catch (ParseException | JOSEException e) {
			logger.error("validateAecinParam: Exception while parsing", e);
			throw new CustomSecurityException("validateAecinParam: aecin param not matching");
		}
	}

	public void validateCiscinParam(String token, String ciscinParam) {

		logger.debug("validateCiscinParam: ciscinParam = {}", ciscinParam);

		try {
			SignedJWT parseToken = parseToken(token);
			if (parseToken.getJWTClaimsSet().getClaim("CISCIN") != null) {
				String ciscinTokenParam = (String) parseToken.getJWTClaimsSet().getClaim("CISCIN");
				logger.debug("validateCiscinParam: ciscinTokenParam from token == {}", ciscinTokenParam);
				if (!ciscinParam.equals(ciscinTokenParam)) {
					logger.error(
							"Token validation failed: CISCIN in the request ({}) does not match CISCIN in the token ({})",
							ciscinParam, ciscinTokenParam);
					throw new CustomSecurityException("validateCiscinParam: ciscin param not matching");
				}
			} else {
				logger.error("ciscin is not found in the token claims set");
				throw new CustomSecurityException("validateCiscinParam: ciscin param is not found in the token");
			}
		} catch (ParseException | JOSEException e) {
			logger.error("validateCiscinParam: Exception while parsing", e);
			throw new CustomSecurityException("validateCiscinParam: ciscin param not matching");
		}
	}

	public void validateOtherParam(String token, String paramName, String paramValue) {

		logger.debug("validateOtherParam: paramName = {}", paramName);

		try {
			SignedJWT parseToken = parseToken(token);
			if (parseToken.getJWTClaimsSet().getClaim(paramName) != null) {
				String otherTokenParam = (String) parseToken.getJWTClaimsSet().getClaim(paramName);
				logger.debug("validateOtherParam: otherTokenParam from token == {}", otherTokenParam);
				if (!paramValue.equals(otherTokenParam)) {
					logger.error(
							"Token validation failed: Param in the request ({}) does not match param in the token ({})",
							paramValue, otherTokenParam);
					throw new CustomSecurityException("validateOtherParam: " + paramName + " param not matching");
				}
			} else {
				logger.error("{} is not found in the token claims set", paramName);
				throw new CustomSecurityException(
						"validateOtherParam: " + paramName + " param is not found in the token");
			}
		} catch (ParseException | JOSEException e) {
			logger.error("validateOtherParam: Exception while parsing", e);
			throw new CustomSecurityException("validateOtherParam: param not matching");
		}
	}

	public void validateOtherParam(String token, String paramName1, String paramValue1, String paramName2, String paramValue2) {

		logger.debug("validateOtherParam: paramName1 = {}, paramName2 = {}", paramName1, paramName2);

		try {
			SignedJWT parseToken = parseToken(token);
			if (parseToken.getJWTClaimsSet().getClaim(paramName1) != null || parseToken.getJWTClaimsSet().getClaim(paramName2) != null) {
				String otherTokenParam1 = (String) parseToken.getJWTClaimsSet().getClaim(paramName1);
				String otherTokenParam2 = (String) parseToken.getJWTClaimsSet().getClaim(paramName2);
				logger.debug("validateOtherParam: otherTokenParam1 from token == {}", otherTokenParam1);
				logger.debug("validateOtherParam: otherTokenParam2 from token == {}", otherTokenParam2);
				if (!((paramValue1 != null && paramValue1.equals(otherTokenParam1)) 
						|| (paramValue2 != null && paramValue2.equals(otherTokenParam2)))) {
					logger.error(
							"Token validation failed: Param in the request ({}/{}) does not match param in the token ({}/{})",
							paramValue1, paramValue2, otherTokenParam1, otherTokenParam2);
					throw new CustomSecurityException("validateOtherParam: " + paramName1 + " or " + paramName2 + " param not matching");
				}
			} else {
				logger.error("{}/{} is not found in the token claims set", paramName1, paramName2);
				throw new CustomSecurityException(
						"validateOtherParam: " + paramName1 + " or " + paramName2 + " param is not found in the token");
			}
		} catch (ParseException | JOSEException e) {
			logger.error("validateOtherParam: Exception while parsing", e);
			throw new CustomSecurityException("validateOtherParam: param not matching");
		}
	}

	public void validateWithoutParam(String token) {

		logger.debug("validateWithoutParam");

		try {
			@SuppressWarnings("unused")
			SignedJWT parseToken = parseToken(token);
		} catch (ParseException | JOSEException e) {
			logger.error("validateWithoutParam: Exception while parsing", e);
			throw new CustomSecurityException("validateWithoutParam: JWT Token can't be verified");
		}
	}

	private boolean isTokenExpired(Date tokenExpDate) {
		boolean returnVal = true;
		if (null != tokenExpDate) {

			logger.debug("tokenExpDate=={}", tokenExpDate);
			Date currentDate = new Date(System.currentTimeMillis());
			logger.debug("currentDate=={}", currentDate);

			if (tokenExpDate.getTime() > currentDate.getTime()) {
				logger.debug("Token is still Valid");
				returnVal = false;
			} else {
				logger.debug("Token is expired");
				returnVal = true;
			}

		}
		return returnVal;
	}
}
