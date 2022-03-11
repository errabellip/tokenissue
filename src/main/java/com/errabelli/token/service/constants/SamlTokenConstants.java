package com.errabelli.token.service.constants;

public final class SamlTokenConstants {

	private SamlTokenConstants() {

	}

	// Pietech
	public static final String ISSUER = "SunTrust Bank";
	public static final String ATTR_GUEST_ID = "GuestID";
	public static final String ATTR_HOUSEHOLD_ID = "HouseholdId";
	public static final String ATTR_ENTITLEMENTS = "Entitlements";
	public static final String ATTR_IS_GUEST = "isGuest";

	public static final String SSP_ISSUER = "https://r360online.com";
	public static final String SSP_APP_NAME = "SSP";
	public static final String SAML_IR_NAME_ID = "https://wfs.raam.com/trust";
	public static final String SAML_IR_SSO_ATTRIBUTE = "http://schemas.wfs.com/2014/01/identity/claims/SSOClaim";

	// Yodlee Constants
	public static final String YODLEE_ATTR = "YodleeAttributes";
	public static final String YODLEE_DEST_URL = "http://sp.example.org/endpoint";
	public static final String YODLEE_ISSUER = "SunTrustBank";

	// FutureAdvisor
	public static final String ATTR_YODLEE_ID = "YodleeId";

	// SummitView
	public static final String ATTR_APPLICATION_NAME = "ApplicationName";

	// Mortgage
	public static final String ATTR_EMAIL = "Email";
	public static final String ATTR_LAST_4_SSN = "Last4SSN";
	public static final String ATTR_CLIENT_NUMBER = "ClientNumber";
	public static final String ATTR_ACCESS_ID = "AccessID";
	public static final String ATTR_LOAN_NUMBER = "LoanNumber";
	public static final String ATTR_SITE_ID = "SiteID";
}
