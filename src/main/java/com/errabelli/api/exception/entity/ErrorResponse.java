package com.errabelli.api.exception.entity;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ErrorResponse {
	private static Logger logger = LoggerFactory.getLogger(ErrorResponse.class);

	public ErrorResponse() {
		super();
	}

	public ErrorResponse(String uniqueErrorId, HttpStatus httpStatusCode, String applicationCode,
			String exceptionMessage, long timestamp) {
		super();
		ErrorDetail errorDetail = new ErrorDetail(uniqueErrorId, httpStatusCode, applicationCode, exceptionMessage, timestamp);
		this.addError(errorDetail);
	}
	
	public ErrorResponse(String uniqueErrorId, HttpStatus httpStatusCode, String applicationCode,
			String exceptionMessage) {
		super();
		ErrorDetail errorDetail = new ErrorDetail(uniqueErrorId, httpStatusCode, applicationCode, exceptionMessage);
		this.addError(errorDetail);
	}

	public ErrorResponse(HttpStatus httpStatusCode, String applicationCode, String exceptionMessage, long timestamp) {
		this(UUID.randomUUID().toString(), httpStatusCode, applicationCode, exceptionMessage, timestamp);
	}
	
	public ErrorResponse(HttpStatus httpStatusCode, String applicationCode, String exceptionMessage) {
		this(UUID.randomUUID().toString(), httpStatusCode, applicationCode, exceptionMessage);
	}

	private List<ErrorDetail> errors;

	public List<ErrorDetail> getErrors() {
		return errors;
	}
	
	@JsonIgnore
	public String getFirstErrorCode() {
		String errorCode = null;
		if(errors != null && errors.size() > 0) {
			ErrorDetail errorDetail = errors.get(0);
			if(errorDetail != null) {
				errorCode = errorDetail.getCode();
			}
		}
		return errorCode;
	}

	public void setErrors(List<ErrorDetail> errors) {
		this.errors = errors;
	}

	public void addError(ErrorDetail error) {
		if (errors == null) {
			errors = new ArrayList<ErrorDetail>();
		}
		errors.add(error);
	}
	
	@Override
	public String toString() {
		return ReflectionToStringBuilder.toString(this);
	}
	
	public void logErrorResponse() {
		StringWriter writer = new StringWriter();
		ObjectMapper objectMapper = new ObjectMapper();
		try {
			objectMapper.writeValue(writer, this);
			String responseJsonSerializedString =writer.toString();
			logger.error("errors: {}", responseJsonSerializedString);
		} catch (Exception e) {
			logger.error("Exception occurred while serializing response", e);
			logger.error("falling back to toString errors: {}", this);
		}
	}
	
}
