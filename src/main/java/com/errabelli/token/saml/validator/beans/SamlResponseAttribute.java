package com.errabelli.token.saml.validator.beans;

public class SamlResponseAttribute {
	private String name;
	private String value;

	public SamlResponseAttribute(String name, String value) {
		super();
		this.name = name;
		this.value = value;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	@Override
	public String toString() {
		return "SamlResponseAttribute [name=" + name + ", value=" + value + "]";
	}
}
