package com.errabelli.token.jwt.controller;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.errabelli.token.service.constants.GenericConstant;
import com.errabelli.token.service.security.util.JwtTokenGenerator;

/**
 * @author uisr96
 *
 *         Main Controller to control request for authentication and key
 *         generation.
 * 
 *         The key sent in header is base64 AES encrypted key with 128 bits.
 * 
 *         Inputparams in header: secretkey + username + role
 * 
 */
@RestController
@RequestMapping("/${token.api.version}")
public class TokenIssuerController {

	@Autowired
	JwtTokenGenerator tokenGenerator;

	private static final Logger logger = LoggerFactory.getLogger(TokenIssuerController.class);

	@RequestMapping(method = RequestMethod.POST, produces = "application/json")
	public String generateToken(@RequestHeader(name = GenericConstant.AECIN_HEADER, required = false) String aecinParam,
			@RequestHeader(name = GenericConstant.CISCIN_HEADER, required = false) String ciscinParam,
			@RequestHeader(name = GenericConstant.PARTYID_HEADER, required = false) String partyIdParam,
			@RequestHeader(name = GenericConstant.USERCOMPANYID_HEADER, required = false) String userCompanyIdParam,
			@RequestHeader(name = GenericConstant.USERGUID_HEADER, required = false) String userGuidParam,
			@RequestHeader(name = GenericConstant.USERID_HEADER, required = false) String userIdParam,
			@RequestHeader(name = GenericConstant.RACFID_HEADER, required = false) String racfIdParam,
			@RequestHeader(name = GenericConstant.USERROLE_HEADER, required = false) String userRoleParam,
			@RequestHeader(name = GenericConstant.INVESTORID_HEADER, required = false) String investorId,
			@RequestHeader(name = GenericConstant.TAXID_HEADER, required = false) String taxId,
			@RequestHeader(name = GenericConstant.CRFCIN_HEADER, required = false) String crfcin,
			@RequestHeader(name = GenericConstant.FUTUREADVISORID_HEADER, required = false) String faId,
			@RequestHeader(name = GenericConstant.SET_EXPIRATION,required =false)String setTokenExpiration,
			HttpServletRequest request, HttpServletResponse response) {

		logger.debug("generateToken Start");
		Map<String, String> headerMap = new HashMap<>();

		Collections.list(request.getHeaderNames()).forEach(headerName -> {
			
			if (headerName.startsWith(GenericConstant.GENERIC_HEADER))
				headerMap.put(headerName, request.getHeader(headerName));
		});
		logger.info("generateToken Optional Params ***********");
		logger.info("generateToken AECIN: ********  [ {} ] ***********", aecinParam);
		logger.info("generateToken CISCIN: ******** [ {} ] ***********", ciscinParam);
		logger.info("generateToken tpartyid: ******** [ {} ] ***********", partyIdParam);
		logger.info("generateToken tusercompanyid: ******** [ {} ] ***********", userCompanyIdParam);
		logger.info("generateToken tuserguid: ******** [ {} ] ***********", userGuidParam);
		logger.info("generateToken tuserid: ******** [ {} ] ***********", userIdParam);
		logger.info("generateToken tracfid: ******** [ {} ] ***********", racfIdParam);
		logger.info("generateToken tuserrole: ******** [ {} ] ***********", userRoleParam);
		logger.info("generateToken t_investorid: ******** [ {} ] ***********", investorId);
		logger.info("generateToken t_taxid: ******** [ {} ] ***********", taxId);
		logger.info("generateToken t_crfcin: ******** [ {} ] ***********", crfcin);
		logger.info("generateToken t_faid: ******** [ {} ] ***********", faId);
		logger.info("generateToken Generic 't' Params: {}", headerMap);
		logger.info("generateToken SetTokenExpiration *****[{}]*****",setTokenExpiration);

		String token = tokenGenerator.createToken(aecinParam, ciscinParam, headerMap,setTokenExpiration);
		logger.trace("generateToken: token={}", token);

		if (token != null) {
			response.setHeader(GenericConstant.RESPONSE_HEADER_AUTH, token);
			response.setStatus(HttpStatus.OK.value());
			return "{\"success\":\"true\",\"message\": \"Successfully generated JWT Token\"}";
		} else {
			response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
			return "{\"failure\":\"true\",\"message\": \"Failure while generating JWT Token\"}";
		}
	}
}
