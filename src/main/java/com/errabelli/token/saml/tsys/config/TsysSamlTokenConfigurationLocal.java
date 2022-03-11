package com.errabelli.token.saml.tsys.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.tsys.util.TsysSamlTokenGenerator;

@Configuration
@Profile("local")
public class TsysSamlTokenConfigurationLocal {

	@Value("${token.saml.tsys.local.keystore.location}")
	private String jksPath;

	@Value("${token.saml.tsys.local.keystore.password}")
	private String keystorePassword;

	@Value("${token.saml.tsys.local.keystore.alias}")
	private String keystoreAlias;

	@Value("${token.saml.tsys.local.keystore.key.password}")
	private String pkeyPassword;

	@Bean
	public TsysSamlTokenGenerator getTsysSamlTokenGeneratorLocal() {
		return new TsysSamlTokenGenerator(jksPath, keystorePassword, keystoreAlias, pkeyPassword);
	}
}
