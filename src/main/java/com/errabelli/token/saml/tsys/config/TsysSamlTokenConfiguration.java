package com.errabelli.token.saml.tsys.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.tsys.util.TsysSamlTokenGenerator;

@Configuration
@Profile("!local")
public class TsysSamlTokenConfiguration {

	@Bean
	public TsysSamlTokenGenerator getTsysSamlTokenGenerator() {
		return new TsysSamlTokenGenerator(System.getenv("DAI_KEY_STORE_LOCATION"), System.getenv("DAI_KEY_STORE_PASSWORD"),
				System.getenv("DAI_KEY_STORE_FED_ALIAS"), System.getenv("DAI_KEY_STORE_FED_KEY_PASSWORD"));
	}
}
