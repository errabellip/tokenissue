package com.errabelli.token.saml.validator.beans;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

public class SamlResponseExtract {

	@JsonInclude(value = JsonInclude.Include.NON_NULL)
	private String nameID;

	@JsonInclude(value = JsonInclude.Include.NON_NULL)
	private String recipient;

	@JsonInclude(value = JsonInclude.Include.NON_NULL)
	private String audience;

	@JsonInclude(value = JsonInclude.Include.NON_EMPTY)
	private List<SamlResponseAttribute> attributes;

	public SamlResponseExtract(String nameID, String recipient, String audience,
			List<SamlResponseAttribute> attributes) {
		super();
		this.nameID = nameID;
		this.recipient = recipient;
		this.audience = audience;
		this.attributes = attributes;
	}

	public String getNameID() {
		return nameID;
	}

	public void setNameID(String nameID) {
		this.nameID = nameID;
	}

	public String getRecipient() {
		return recipient;
	}

	public void setRecipient(String recipient) {
		this.recipient = recipient;
	}

	public String getAudience() {
		return audience;
	}

	public void setAudience(String audience) {
		this.audience = audience;
	}

	public List<SamlResponseAttribute> getAttributes() {
		return attributes;
	}

	public void setAttributes(List<SamlResponseAttribute> attributes) {
		this.attributes = attributes;
	}

}
