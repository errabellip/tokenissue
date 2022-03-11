package com.errabelli.api.exception.entity;

import java.time.Instant;
import java.util.UUID;

import org.springframework.http.HttpStatus;

public class ErrorDetail {

	private long timestamp;
	private String id, code, title;
	private int status;
	private ErrorSource source;

	public ErrorDetail(String uniqueErrorId, HttpStatus httpStatusCode, String applicationCode,
			String exceptionMessage, long timestamp) {
		super();
		this.timestamp = timestamp;
		this.id = uniqueErrorId;
		this.status = httpStatusCode.value();
		this.code = applicationCode;
		this.title = exceptionMessage;
	}

	public ErrorDetail(String uniqueErrorId, HttpStatus httpStatusCode, String applicationCode,
			String exceptionMessage) {
		this(UUID.randomUUID().toString(), httpStatusCode, applicationCode, exceptionMessage, Instant.now().toEpochMilli());
	}
	
	public ErrorDetail(HttpStatus httpStatusCode, String applicationCode, String exceptionMessage) {
		this(UUID.randomUUID().toString(), httpStatusCode, applicationCode, exceptionMessage);
	}

	public ErrorDetail(HttpStatus httpStatusCode, String applicationCode, String exceptionMessage, String errorSourcePointer) {
		this(UUID.randomUUID().toString(), httpStatusCode, applicationCode, exceptionMessage);
		this.source = new ErrorSource(errorSourcePointer);
		
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public int getStatus() {
		return status;
	}

	public void setStatus(int status) {
		this.status = status;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public ErrorSource getSource() {
		return source;
	}

	public void setSource(ErrorSource source) {
		this.source = source;
	}

	public long getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}
}
