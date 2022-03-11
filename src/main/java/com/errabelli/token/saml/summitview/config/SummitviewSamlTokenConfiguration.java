package com.errabelli.token.saml.summitview.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.summitview.util.SummitviewSamlTokenGenerator;

@Configuration
@Profile("!local")
public class SummitviewSamlTokenConfiguration {

	@Bean
	public SummitviewSamlTokenGenerator getSummitviewSamlTokenGenerator() {
		return new SummitviewSamlTokenGenerator(System.getenv("DAI_KEY_STORE_LOCATION"),
				System.getenv("DAI_KEY_STORE_PASSWORD"), System.getenv("DAI_KEY_STORE_FED_ALIAS"),
				System.getenv("DAI_KEY_STORE_FED_KEY_PASSWORD"));
	}
}
