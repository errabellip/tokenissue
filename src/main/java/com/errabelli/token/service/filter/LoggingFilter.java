package com.errabelli.token.service.filter;

import java.io.IOException;
import java.util.UUID;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 
 * @author Kingsly Theodar Rajasekar
 *
 */
@Configuration
public class LoggingFilter {
	private static final Logger logger = LoggerFactory.getLogger(LoggingFilter.class);
	private static final String CORRELATION_ID = "correlationid";

	@Bean
	public FilterRegistrationBean loggingCorrelationIdAdderFilterRegistration() {

		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(loggingCorrelationIdAdderFilter());
		registration.addUrlPatterns("/*");
		registration.setName("loggingCorrelationIdAdderFilter");
		registration.setOrder(1);
		return registration;
	}

	public Filter loggingCorrelationIdAdderFilter() {
		return new Filter() {

			@Override
			public void init(FilterConfig filterConfig) throws ServletException {
				//Overriden method
			}

			@Override
			public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
					throws IOException, ServletException {
				try {
					HttpServletRequest httpReq = (HttpServletRequest) request;
					String correlationHeader = httpReq.getHeader(CORRELATION_ID);
					if (correlationHeader == null) {
						correlationHeader = UUID.randomUUID().toString();
						logger.debug("correlationId was missing in header, generated one, {}", correlationHeader);
					}
					MDC.put(CORRELATION_ID, correlationHeader);
				} finally {
					chain.doFilter(request, response);
					try {
						MDC.remove(CORRELATION_ID);
					} catch (Exception e) {
						// Should never happen, but failing which should not
						// cause anything else to fail
						logger.error("Removing correlation id failed", e);
					}
				}
			}

			@Override
			public void destroy() {
				//Overriden method
			}
		};
	}
}
