package com.errabelli.token.saml.ir.beans;

public class SamlAssertionResponse {

	private String samlAssertion;

	public SamlAssertionResponse(String samlAssertion) {
		super();
		this.samlAssertion = samlAssertion;
	}

	public String getSamlAssertion() {
		return samlAssertion;
	}

	public void setSamlAssertion(String samlAssertion) {
		this.samlAssertion = samlAssertion;
	}
}
