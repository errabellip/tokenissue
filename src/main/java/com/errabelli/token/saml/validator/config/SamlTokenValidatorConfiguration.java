package com.errabelli.token.saml.validator.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.validator.util.SamlExtractor;

@Configuration
@Profile("!local")
public class SamlTokenValidatorConfiguration {

	@Bean
	public SamlExtractor getSamlExtractor() {
		return new SamlExtractor(System.getenv("DAI_KEY_STORE_LOCATION"), System.getenv("DAI_KEY_STORE_PASSWORD"),
				System.getenv("DAI_KEY_STORE_ISSUER_ALIAS_PREFIX"));
	}
}
