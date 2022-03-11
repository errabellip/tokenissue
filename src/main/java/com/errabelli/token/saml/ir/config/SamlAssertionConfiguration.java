package com.errabelli.token.saml.ir.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.ir.util.SamlAssertionGenerator;

@Configuration
@Profile("!local")
public class SamlAssertionConfiguration {

	@Bean
	public SamlAssertionGenerator getSamlAssertionGenerator() {
		return new SamlAssertionGenerator(System.getenv("DAI_IR_KEY_STORE_LOCATION"),
				System.getenv("DAI_IR_KEY_STORE_PASSWORD"), System.getenv("DAI_IR_KEY_STORE_ALIAS"),
				System.getenv("DAI_IR_KEY_STORE_KEYPASSWORD"));
	}
}
