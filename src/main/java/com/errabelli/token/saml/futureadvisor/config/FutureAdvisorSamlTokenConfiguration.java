package com.errabelli.token.saml.futureadvisor.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.futureadvisor.util.FutureAdvisorSamlTokenGenerator;

@Configuration
@Profile("!local")
public class FutureAdvisorSamlTokenConfiguration {

	@Bean
	public FutureAdvisorSamlTokenGenerator getFutureAdvisorSamlTokenGenerator() {
		return new FutureAdvisorSamlTokenGenerator(System.getenv("DAI_KEY_STORE_LOCATION"),
				System.getenv("DAI_KEY_STORE_PASSWORD"), System.getenv("DAI_KEY_STORE_FED_ALIAS"),
				System.getenv("DAI_KEY_STORE_FED_KEY_PASSWORD"));
	}
}
