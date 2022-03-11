package com.errabelli.token.service.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;


/**
 * Custom Exception class, later it will be modified
 * 
 * @author uisr96
 *
 */
@ResponseStatus(value = HttpStatus.NOT_FOUND, reason = "Exception thrown in JWT Token generation")
public class JWTTokenException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 68759893106801804L;

	public JWTTokenException(String message, Throwable cause) {
		super(message, cause);
	}
}
