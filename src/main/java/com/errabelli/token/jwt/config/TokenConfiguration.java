package com.errabelli.token.jwt.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.errabelli.token.service.security.util.JwtTokenGenerator;

@Configuration
public class TokenConfiguration {

	@Value("${jwt.token.expiration.time}")
	public int tokenExpirationTime;

	@Value("${jwt.secret}")
	public String secretkey;

	@Bean
	@ConditionalOnMissingBean
	public JwtTokenGenerator jwtCsrfTokenRepository() {
		return new JwtTokenGenerator(secretkey, tokenExpirationTime);
	}

}
