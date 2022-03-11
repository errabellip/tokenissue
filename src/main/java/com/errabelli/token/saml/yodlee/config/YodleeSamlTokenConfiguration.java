package com.errabelli.token.saml.yodlee.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.yodlee.util.YodleeSamlTokenGenerator;

@Configuration
@Profile("!local")
public class YodleeSamlTokenConfiguration {

	@Bean
	public YodleeSamlTokenGenerator getYodleeSamlTokenGenerator() {
		return new YodleeSamlTokenGenerator(System.getenv("DAI_YODLEE_KEY_STORE_LOCATION"),
				System.getenv("DAI_YODLEE_KEY_STORE_PASSWORD"), System.getenv("DAI_YODLEE_KEY_STORE_ALIAS"));
	}
}
