package com.errabelli.token.saml.wealthscape.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.wealthscape.util.WealthscapeSamlTokenGenerator;

@Configuration
@Profile("local")
public class WealthscapeSamlTokenConfigurationLocal {

	@Value("${token.saml.wealthscape.local.keystore.location}")
	private String jksPath;

	@Value("${token.saml.wealthscape.local.keystore.password}")
	private String keystorePassword;

	@Value("${token.saml.wealthscape.local.keystore.alias}")
	private String keystoreAlias;

	@Value("${token.saml.wealthscape.local.keystore.key.password}")
	private String pkeyPassword;

	@Value("${token.saml.wealthscape.local.keystore.spcert.alias}")
	private String keystoreSpCertAlias;

	@Bean
	public WealthscapeSamlTokenGenerator getWealthscapeSamlTokenGeneratorLocal() {
		return new WealthscapeSamlTokenGenerator(jksPath, keystorePassword, keystoreAlias, pkeyPassword, keystoreSpCertAlias);
	}
}
