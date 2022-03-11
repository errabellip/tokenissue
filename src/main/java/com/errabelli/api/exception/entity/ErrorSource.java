package com.errabelli.api.exception.entity;

public class ErrorSource {

	private String pointer;

	public ErrorSource(String pointer) {
		super();
		this.pointer = normalize(pointer);
	}

	// Convert from dot dereference to near JSON Pointer notation
	// suggested in jsonapi (RFC6901(
	private String normalize(String nonStandardPointer) {
		if (nonStandardPointer == null) {
			pointer = "UNKNOWN";
		} else {

			StringBuilder stringBuilder = new StringBuilder("/");
			stringBuilder.append(nonStandardPointer.replace(".", "/"));
			pointer = stringBuilder.toString();
		}
		return pointer;
	}

	public String getPointer() {
		return pointer;
	}

	public void setPointer(String pointer) {
		this.pointer = pointer;
	}
}
