package com.errabelli.token.saml.yodlee.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.yodlee.util.YodleeSamlTokenGenerator;

@Configuration
@Profile("local")
public class YodleeSamlTokenConfigurationLocal {

	@Value("${token.saml.local.Yodlee.keystore.location}")
	private String jksPath;

	@Value("${token.saml.local.Yodlee.keystore.password}")
	private String keystorePassword;

	@Value("${token.saml.local.Yodlee.keystore.alias}")
	private String keystoreAlias;

	@Bean
	public YodleeSamlTokenGenerator getYodleeSamlTokenGeneratorLocal() {
		return new YodleeSamlTokenGenerator(jksPath, keystorePassword, keystoreAlias);
	}

}
