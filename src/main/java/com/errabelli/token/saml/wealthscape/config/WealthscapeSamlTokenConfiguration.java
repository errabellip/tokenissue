package com.errabelli.token.saml.wealthscape.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.wealthscape.util.WealthscapeSamlTokenGenerator;

@Configuration
@Profile("!local")
public class WealthscapeSamlTokenConfiguration {

	@Bean
	public WealthscapeSamlTokenGenerator getWealthscapeSamlTokenGenerator() {
		return new WealthscapeSamlTokenGenerator(System.getenv("DAI_KEY_STORE_LOCATION"),
				System.getenv("DAI_KEY_STORE_PASSWORD"), System.getenv("DAI_KEY_STORE_FED_ALIAS"),
				System.getenv("DAI_KEY_STORE_FED_KEY_PASSWORD"), System.getenv("DAI_KEY_STORE_WEALTHSCAPE_SP_CERT_ALIAS"));
	}
}
