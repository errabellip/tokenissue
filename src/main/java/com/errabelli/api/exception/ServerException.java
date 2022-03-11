package com.errabelli.api.exception;

import org.springframework.http.HttpStatus;

public class ServerException extends BaseException {

	private static final long serialVersionUID = 1L;

	public ServerException(String applicationCode, String errorMessage, HttpStatus httpStatusCode) {
		super(applicationCode, errorMessage, httpStatusCode);
	}

	public ServerException(String applicationCode, String errorMessage) {
		this(applicationCode, errorMessage, HttpStatus.INTERNAL_SERVER_ERROR);
	}

	public ServerException(String applicationCode, String errorMessage, Throwable ex) {
		super(applicationCode, errorMessage, HttpStatus.INTERNAL_SERVER_ERROR, ex);
	}

}
