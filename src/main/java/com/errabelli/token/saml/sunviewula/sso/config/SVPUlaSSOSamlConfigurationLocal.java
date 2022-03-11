package com.errabelli.token.saml.sunviewula.sso.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.errabelli.token.saml.sunviewula.sso.util.IPUlaSSOSamlGenerator;
import com.errabelli.token.saml.sunviewula.sso.util.IRUlaSSOSamlGenerator;
import com.errabelli.token.saml.sunviewula.sso.util.OLCUlaSSOSamlGenerator;

@Configuration
@Profile("local")
public class SVPUlaSSOSamlConfigurationLocal {

	@Value("${token.saml.svp.ula.local.keystore.location}")
	private String jksPath;

	@Value("${token.saml.svp.ula.local.keystore.password}")
	private String keystorePassword;

	@Value("${token.saml.svp.ula.local.keystore.keypassword}")
	private String keyPassword;

	@Value("${token.saml.svp.ula.local.keystore.alias}")
	private String keystoreAlias;

	@Bean
	public IRUlaSSOSamlGenerator getIRUlaSSOSamlGeneratorLocal() {
		return new IRUlaSSOSamlGenerator(jksPath, keystorePassword, keystoreAlias, keyPassword);
	}

	@Bean
	public IPUlaSSOSamlGenerator getIPUlaSSOSamlGeneratorLocal() {
		return new IPUlaSSOSamlGenerator(jksPath, keystorePassword, keystoreAlias, keyPassword);
	}

	@Bean
	public OLCUlaSSOSamlGenerator getOLCUlaSSOSamlGeneratorLocal() {
		return new OLCUlaSSOSamlGenerator(jksPath, keystorePassword, keystoreAlias, keyPassword);
	}
}
