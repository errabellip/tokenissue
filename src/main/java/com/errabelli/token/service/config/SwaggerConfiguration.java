package com.errabelli.token.service.config;

import static springfox.documentation.builders.PathSelectors.regex;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@Configuration
@ConditionalOnProperty(name = { "swagger.ui.enabled" }, havingValue = "true")
@EnableSwagger2
public class SwaggerConfiguration {

	@Value("${token.api.version}")
	private String tokenApiVersion;

	@Value("${token.saml.pietech.api.version}")
	private String tokenSamlPietechApiVersion;

	@Value("${token.saml.ir.api.version}")
	private String tokenSamlIRApiVersion;

	@Value("${token.saml.yodlee.api.version}")
	private String tokenSamlYodleeApiVersion;

	@Value("${token.saml.futureadvisor.api.version}")
	private String tokenSamlFutureAdvisorApiVersion;

	@Value("${token.saml.tsys.api.version}")
	private String tokenSamlTsysApiVersion;

	@Value("${token.saml.wealthscape.api.version}")
	private String tokenSamlWealthscapeApiVersion;

	@Value("${token.saml.summitview.api.version}")
	private String tokenSamlSummitviewApiVersion;

	@Value("${token.saml.mortgage.api.version}")
	private String tokenSamlMortgageApiVersion;

	@Value("${token.saml.validator.api.version}")
	private String tokenSamlValidatorApiVersion;
	/*
	 * For swagger api enablement
	 */

	@Bean
    public Docket newsApi() {
        return new Docket(DocumentationType.SWAGGER_2)
                .groupName("token")
                .apiInfo(apiInfo())
                .select()
                .paths(regex("/"+tokenApiVersion+".*|"
                		+"/saml/pietech/"+tokenSamlPietechApiVersion+".*|"
                		+"/saml/tsys/"+tokenSamlTsysApiVersion+".*|"
                		+"/saml/wealthscape/"+tokenSamlWealthscapeApiVersion+".*|"
                		+"/saml/summitview/"+tokenSamlSummitviewApiVersion+".*|"
                		+"/saml/mortgage/"+tokenSamlMortgageApiVersion+".*|"
                		+"/saml/IR/" + tokenSamlIRApiVersion + ".*|"
                		+"/saml/yodlee/" + tokenSamlYodleeApiVersion + ".*|"
                		+"/saml/futureadvisor/" + tokenSamlFutureAdvisorApiVersion + ".*|"
                		+"/saml/svp/ula/" + tokenSamlIRApiVersion + ".*|"
                		+"/saml/validator/" + tokenSamlValidatorApiVersion + ".*"))
                .build();
    }
     
    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("********** TOKEN API SWAGGER DOCUMENTATION **********")
                .description("TOKEN API DETAILS")
                .version("1.0")
                .build();
    }
}
