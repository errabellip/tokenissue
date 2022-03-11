package com.errabelli.token.saml.pietech.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.pietech.util.SamlTokenGenerator;

@Configuration
@Profile("!local")
public class SamlTokenConfiguration {

	@Bean
	public SamlTokenGenerator getSamlTokenGenerator() {
		return new SamlTokenGenerator(System.getenv("DAI_KEY_STORE_LOCATION"), System.getenv("DAI_KEY_STORE_PASSWORD"),
				System.getenv("DAI_KEY_STORE_ALIAS"));
	}
}
