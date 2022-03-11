package com.errabelli.api.exception;

import org.springframework.http.HttpStatus;

public class BusinessException extends BaseException {

	public BusinessException(String applicationCode, String errorMessage, HttpStatus httpStatusCode) {
		super(applicationCode, errorMessage, httpStatusCode);
	}

	public BusinessException(String applicationCode, String errorMessage) {
		this(applicationCode, errorMessage, HttpStatus.BAD_REQUEST);
	}

	public BusinessException(String applicationCode, String errorMessage, Throwable ex) {
		super(applicationCode, errorMessage, HttpStatus.BAD_REQUEST, ex);
	}

	public BusinessException(String applicationCode, String errorMessage, HttpStatus httpStatusCode, Throwable ex) {
		super(applicationCode, errorMessage, httpStatusCode, ex);
	}
}
