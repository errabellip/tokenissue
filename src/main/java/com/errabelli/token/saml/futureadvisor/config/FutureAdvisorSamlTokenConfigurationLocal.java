package com.errabelli.token.saml.futureadvisor.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.futureadvisor.util.FutureAdvisorSamlTokenGenerator;

@Configuration
@Profile("local")
public class FutureAdvisorSamlTokenConfigurationLocal {

	@Value("${token.saml.futureadvisor.local.keystore.location}")
	private String jksPath;

	@Value("${token.saml.futureadvisor.local.keystore.password}")
	private String keystorePassword;

	@Value("${token.saml.futureadvisor.local.keystore.alias}")
	private String keystoreAlias;

	@Value("${token.saml.futureadvisor.local.keystore.key.password}")
	private String pkeyPassword;

	@Bean
	public FutureAdvisorSamlTokenGenerator getFutureAdvisorSamlTokenGeneratorLocal() {
		return new FutureAdvisorSamlTokenGenerator(jksPath, keystorePassword, keystoreAlias, pkeyPassword);
	}
}
