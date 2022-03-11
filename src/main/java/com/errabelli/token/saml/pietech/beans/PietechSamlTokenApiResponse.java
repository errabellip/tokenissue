package com.errabelli.token.saml.pietech.beans;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(value=JsonInclude.Include.NON_EMPTY)
public class PietechSamlTokenApiResponse {

	private PietechSamlToken samlToken;

	public PietechSamlTokenApiResponse(PietechSamlToken samlToken) {
		super();
		this.samlToken = samlToken;
	}

	public PietechSamlTokenApiResponse() {
		super();
	}

	public PietechSamlToken getSamlToken() {
		return samlToken;
	}

	public void setSamlToken(PietechSamlToken samlToken) {
		this.samlToken = samlToken;
	}

}
