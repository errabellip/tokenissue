package com.errabelli.token.saml.yodlee.controller;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.errabelli.token.saml.yodlee.beans.YodleeSamlReq;
import com.errabelli.token.saml.yodlee.beans.YodleeSamlTokenResponse;
import com.errabelli.token.saml.yodlee.util.YodleeSamlTokenGenerator;

@RestController
@RequestMapping("/saml/yodlee/${token.saml.yodlee.api.version}")
public class YodleeSamlTokenIssuerController {

	private static final Logger logger = LoggerFactory.getLogger(YodleeSamlTokenIssuerController.class);

	@Autowired
	YodleeSamlTokenGenerator yodleeSamlTokenGenerator;

	@RequestMapping(value = "/{nameId}", method = RequestMethod.POST, consumes = "application/hal+json")
	public YodleeSamlTokenResponse generateYodleeSamlToken(@PathVariable("nameId") String nameId,
			@RequestBody YodleeSamlReq yodSmlReq, @RequestHeader("Authorization") String authorizationToken,
			HttpServletRequest request) {

		logger.debug("Entered YodleeSamlTokenIssuerController.generateYodleeSamlToken");

		YodleeSamlTokenResponse yodleeSamlTokenResponse = new YodleeSamlTokenResponse();
		String yodleeAttribute = yodSmlReq.getYodleeAttribute();
		String token = yodleeSamlTokenGenerator.createToken(nameId, yodleeAttribute);
		yodleeSamlTokenResponse.setYodleeSamlToken(token);

		logger.debug("Exiting YodleeSamlTokenIssuerController.generateYodleeSamlToken");
		return yodleeSamlTokenResponse;
	}

}
