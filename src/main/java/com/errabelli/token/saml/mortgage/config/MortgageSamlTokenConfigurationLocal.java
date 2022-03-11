package com.errabelli.token.saml.mortgage.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.mortgage.util.MortgageSamlTokenGenerator;

@Configuration
@Profile("local")
public class MortgageSamlTokenConfigurationLocal {

	@Value("${token.saml.mortgage.local.keystore.location}")
	private String jksPath;

	@Value("${token.saml.mortgage.local.keystore.password}")
	private String keystorePassword;

	@Value("${token.saml.mortgage.local.keystore.alias}")
	private String keystoreAlias;

	@Value("${token.saml.mortgage.local.keystore.key.password}")
	private String pkeyPassword;

	@Value("${token.saml.mortgage.local.keystore.spcert.alias}")
	private String keystoreSpCertAlias;

	@Bean
	public MortgageSamlTokenGenerator getMortgageSamlTokenGeneratorLocal() {
		return new MortgageSamlTokenGenerator(jksPath, keystorePassword, keystoreAlias, pkeyPassword, keystoreSpCertAlias);
	}
}
