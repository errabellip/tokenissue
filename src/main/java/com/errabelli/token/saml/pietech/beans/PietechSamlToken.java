package com.errabelli.token.saml.pietech.beans;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(value=JsonInclude.Include.NON_EMPTY)
public class PietechSamlToken {

	private String token;
	private String mgpSsoUrl;

	public PietechSamlToken() {
		super();
	}

	public PietechSamlToken(String token, String mgpSsoUrl) {
		super();
		this.token = token;
		this.mgpSsoUrl = mgpSsoUrl;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public String getMgpSsoUrl() {
		return mgpSsoUrl;
	}

	public void setMgpSsoUrl(String mgpSsoUrl) {
		this.mgpSsoUrl = mgpSsoUrl;
	}

	@Override
	public String toString() {
		return "SamlToken [token=" + token + ", mgpSsoUrl=" + mgpSsoUrl + "]";
	}
}
