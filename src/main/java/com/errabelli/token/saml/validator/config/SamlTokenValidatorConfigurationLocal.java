package com.errabelli.token.saml.validator.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.validator.util.SamlExtractor;

@Configuration
@Profile("local")
public class SamlTokenValidatorConfigurationLocal {

	@Value("${token.saml.validator.local.keystore.location}")
	private String jksPath;

	@Value("${token.saml.validator.local.keystore.password}")
	private String keystorePassword;

	@Value("${token.saml.validator.local.keystore.alias.prefix}")
	private String issuerKeyAliasPrefix;

	@Bean
	public SamlExtractor getSamlExtractor() {
		return new SamlExtractor(jksPath, keystorePassword, issuerKeyAliasPrefix);
	}
}
