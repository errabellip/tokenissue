package com.errabelli.api.exception;

import java.util.UUID;

import org.springframework.http.HttpStatus;

public class BaseException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = -2347180294202750001L;
	private final String uniqueErrorId;
	private final String applicationCode;
	private final HttpStatus httpStatusCode;

	public BaseException(String applicationCode, String errorMessage, HttpStatus httpStatusCode) {
		this(applicationCode,  errorMessage,  httpStatusCode, null);
	}

	public BaseException(String applicationCode, String errorMessage, HttpStatus httpStatusCode, Throwable ex) {
		super(errorMessage, ex);
		uniqueErrorId = UUID.randomUUID().toString();
		this.httpStatusCode = httpStatusCode;
		this.applicationCode = applicationCode;
	}

	public String getUniqueErrorId() {
		return uniqueErrorId;
	}


	public String getApplicationCode() {
		return applicationCode;
	}


	public HttpStatus getHttpStatusCode() {
		return httpStatusCode;
	}


}
