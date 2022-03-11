package com.errabelli.api.exception;

import org.springframework.http.HttpStatus;

public class CustomSecurityException extends BaseException {

	public CustomSecurityException(String applicationCode, String errorMessage, HttpStatus httpStatusCode) {
		super(applicationCode, errorMessage, httpStatusCode);
	}

	public CustomSecurityException(String errorMessage) {
		this(ExceptionConstants.GENERAL_CLIENT_FAILURE_CODE, errorMessage, HttpStatus.FORBIDDEN);
	}
	public CustomSecurityException(String applicationCode, String errorMessage) {
		this(applicationCode, errorMessage, HttpStatus.FORBIDDEN);
	}

	public CustomSecurityException(String applicationCode, String errorMessage, Exception ex) {
		super(applicationCode, errorMessage, HttpStatus.FORBIDDEN, ex);
	}

}
