package com.errabelli.token;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

/**
 * 
 * @author uisr96
 *
 */
@SpringBootApplication(scanBasePackages="com.suntrust")
public class TokenIssuerMsApplication {

	private static final String ENVIRONMENT_NAME="DAI_ENV";
	
	public static void main(String[] args) {
		
		String environmentName = System.getenv(ENVIRONMENT_NAME);
		new SpringApplicationBuilder().sources(TokenIssuerMsApplication.class).profiles(environmentName).build().run(args);
		
	}
}
