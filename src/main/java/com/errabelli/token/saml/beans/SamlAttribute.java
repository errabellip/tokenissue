package com.errabelli.token.saml.beans;

import java.util.List;

public class SamlAttribute {

	private final String name;
	private final List<String> values;

	public SamlAttribute(String name, List<String> values) {
	    this.name = name;
	    this.values = values;
	  }

	public String getName() {
		return name;
	}

	public List<String> getValues() {
		return values;
	}

	public String getValue() {
		return String.join(", ", values);
	}

	@Override
	public String toString() {
		return "SAMLAttribute{" + "name='" + name + '\'' + ", values=" + values + '}';
	}
}