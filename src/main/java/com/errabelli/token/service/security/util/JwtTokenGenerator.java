package com.suntrust.token.service.security.util;

import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.suntrust.token.service.exception.JWTTokenException;

/**
 * Utility class to generate authorization token
 */
public class JwtTokenGenerator {

	private static final Logger logger = LoggerFactory.getLogger(JwtTokenGenerator.class);

	private String secret;
	private int tokenExpirationTime;

	public JwtTokenGenerator(String secretKey, int expirationTime) {
		this.secret = secretKey;
		this.tokenExpirationTime = expirationTime;
	}

	/**
	 * Generates a JWT token with AECIN/CISCIN/other params as claims
	 * 
	 * @param aecinParam
	 * @param ciscinParam
	 * @param paramMap
	 * @return
	 * @throws JWTTokenException
	 */
	public String createToken(String aecinParam, String ciscinParam, Map<String, String> paramMap, String setTokenExpiration)
			 {

		String jwtToken = null;
		logger.debug("createToken start");
		
		com.nimbusds.jwt.JWTClaimsSet.Builder jwtBuilder;
		if (setTokenExpiration!=null) {
			
			// Adding the customized field for controlling the expiration time in the JWTtoken
			long setExpiration = Integer.parseInt(setTokenExpiration);
			//Expecting the expiration in seconds from the consumer side.
			setExpiration= TimeUnit.SECONDS.toMillis(setExpiration);
			logger.info("SetExpirationToken Value from request{}",setExpiration);
			jwtBuilder = new JWTClaimsSet.Builder().expirationTime(new Date(System.currentTimeMillis() + setExpiration))
					.jwtID(UUID.randomUUID().toString());
		} else {
			jwtBuilder = new JWTClaimsSet.Builder().expirationTime(new Date(System.currentTimeMillis() + tokenExpirationTime))
					.jwtID(UUID.randomUUID().toString());
		}
		// Set claims - AECIN, CISCIN Params
		jwtBuilder.claim("AECIN", aecinParam).claim("CISCIN", ciscinParam);

		// Set claims - dynamic params that match a pattern
		paramMap.forEach((k, v) -> jwtBuilder.claim(k, v));

		JWTClaimsSet claimsSet = jwtBuilder.build();
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS512), claimsSet);

		// Apply the HMAC protection
		try {
			JWSSigner signer = new MACSigner(secret.getBytes());
			signedJWT.sign(signer);
			jwtToken = signedJWT.serialize();
			// Authorization: Bearer <token>
			jwtToken = "Bearer " + jwtToken;
		} catch (JOSEException e) {
			logger.error("### createToken: Token creation failed ##### ", e);
		}

		logger.debug("createToken end");
		return jwtToken;

	}

}
