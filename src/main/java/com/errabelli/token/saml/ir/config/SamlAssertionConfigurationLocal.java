package com.errabelli.token.saml.ir.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.ir.util.SamlAssertionGenerator;

@Configuration
@Profile("local")
public class SamlAssertionConfigurationLocal {

	@Value("${token.saml.local.IR.keystore.location}")
	private String jksPath;

	@Value("${token.saml.local.IR.keystore.password}")
	private String keystorePassword;

	@Value("${token.saml.local.IR.keystore.keypassword}")
	private String keyPassword;

	@Value("${token.saml.local.IR.keystore.alias}")
	private String keystoreAlias;

	@Bean
	public SamlAssertionGenerator getSamlAssertionGeneratorLocal() {
		return new SamlAssertionGenerator(jksPath, keystorePassword, keystoreAlias, keyPassword);
	}
}
