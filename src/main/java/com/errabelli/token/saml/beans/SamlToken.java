package com.errabelli.token.saml.beans;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(value=JsonInclude.Include.NON_EMPTY)
public class SamlToken {

	private String token;
	private String ssoUrl;

	public SamlToken() {
		super();
	}

	public SamlToken(String token, String ssoUrl) {
		super();
		this.token = token;
		this.ssoUrl = ssoUrl;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public String getSsoUrl() {
		return ssoUrl;
	}

	public void setSsoUrl(String ssoUrl) {
		this.ssoUrl = ssoUrl;
	}

	@Override
	public String toString() {
		return "SamlToken [token=" + token + ", ssoUrl=" + ssoUrl + "]";
	}
}
