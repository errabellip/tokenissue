package com.errabelli.token.saml.sunviewula.sso.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.sunviewula.sso.util.IPUlaSSOSamlGenerator;
import com.errabelli.token.saml.sunviewula.sso.util.IRUlaSSOSamlGenerator;
import com.errabelli.token.saml.sunviewula.sso.util.OLCUlaSSOSamlGenerator;

@Configuration
@Profile("!local")
public class SVPUlaSSOSamlConfiguration {

	@Bean
	public IRUlaSSOSamlGenerator getIRUlaSamlGenerator() {
		return new IRUlaSSOSamlGenerator(System.getenv("DAI_IR_KEY_STORE_LOCATION"),
				System.getenv("DAI_IR_KEY_STORE_PASSWORD"), System.getenv("DAI_SUV_KEY_STORE_FED_ALIAS"),
				System.getenv("DAI_SUV_KEY_STORE_FED_KEY_PASSWORD"));
	}

	@Bean
	public IPUlaSSOSamlGenerator getIPUlaSamlGenerator() {
		return new IPUlaSSOSamlGenerator(System.getenv("DAI_IR_KEY_STORE_LOCATION"),
				System.getenv("DAI_IR_KEY_STORE_PASSWORD"), System.getenv("DAI_SUV_KEY_STORE_FED_ALIAS"),
				System.getenv("DAI_SUV_KEY_STORE_FED_KEY_PASSWORD"));
	}

	@Bean
	public OLCUlaSSOSamlGenerator getOLCUlaSamlGenerator() {
		return new OLCUlaSSOSamlGenerator(System.getenv("DAI_KEY_STORE_LOCATION"),
				System.getenv("DAI_KEY_STORE_PASSWORD"), System.getenv("DAI_KEY_STORE_FED_ALIAS"),
				System.getenv("DAI_KEY_STORE_FED_KEY_PASSWORD"));
	}
}
