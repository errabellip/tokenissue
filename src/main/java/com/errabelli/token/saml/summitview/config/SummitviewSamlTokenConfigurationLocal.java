package com.errabelli.token.saml.summitview.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.summitview.util.SummitviewSamlTokenGenerator;

@Configuration
@Profile("local")
public class SummitviewSamlTokenConfigurationLocal {

	@Value("${token.saml.summitview.local.keystore.location}")
	private String jksPath;

	@Value("${token.saml.summitview.local.keystore.password}")
	private String keystorePassword;

	@Value("${token.saml.summitview.local.keystore.alias}")
	private String keystoreAlias;

	@Value("${token.saml.summitview.local.keystore.key.password}")
	private String pkeyPassword;

	@Bean
	public SummitviewSamlTokenGenerator getSummitviewSamlTokenGeneratorLocal() {
		return new SummitviewSamlTokenGenerator(jksPath, keystorePassword, keystoreAlias, pkeyPassword);
	}
}
