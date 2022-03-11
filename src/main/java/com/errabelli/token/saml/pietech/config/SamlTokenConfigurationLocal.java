package com.errabelli.token.saml.pietech.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.pietech.util.SamlTokenGenerator;

@Configuration
@Profile("local")
public class SamlTokenConfigurationLocal {

	@Value("${token.saml.local.keystore.location}")
	private String jksPath;

	@Value("${token.saml.local.keystore.password}")
	private String keystorePassword;

	@Value("${token.saml.local.keystore.alias}")
	private String keystoreAlias;

	@Bean
	public SamlTokenGenerator getSamlTokenGeneratorLocal() {
		return new SamlTokenGenerator(jksPath, keystorePassword, keystoreAlias);
	}
}
