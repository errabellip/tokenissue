package com.errabelli.token.saml.beans;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(value=JsonInclude.Include.NON_EMPTY)
public class SamlTokenApiResponse {

	private SamlToken samlToken;

	public SamlTokenApiResponse(SamlToken samlToken) {
		super();
		this.samlToken = samlToken;
	}

	public SamlTokenApiResponse() {
		super();
	}

	public SamlToken getSamlToken() {
		return samlToken;
	}

	public void setSamlToken(SamlToken samlToken) {
		this.samlToken = samlToken;
	}

}
