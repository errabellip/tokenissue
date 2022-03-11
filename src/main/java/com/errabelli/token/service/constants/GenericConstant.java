package com.errabelli.token.service.constants;

/**
 * Constant class for JWT Token generation
 * 
 * @author uisr96
 *
 */
public final class GenericConstant {
	
	private GenericConstant(){
		
	}
	public static final String RESPONSE_HEADER_AUTH = "Authorization";
	public static final String AECIN_HEADER ="AECIN";
	public static final String CISCIN_HEADER = "CISCIN";
	public static final String PARTYID_HEADER = "tpartyid";
	public static final String USERCOMPANYID_HEADER = "tusercompanyid";
	public static final String USERGUID_HEADER = "tuserguid";
	public static final String USERID_HEADER = "tuserid";
	public static final String RACFID_HEADER = "tracfid";
	public static final String USERROLE_HEADER = "tuserrole";
	public static final String INVESTORID_HEADER="t_investorid";
	public static final String TAXID_HEADER="t_taxid";
	public static final String CRFCIN_HEADER="t_crfcin";
	public static final String FUTUREADVISORID_HEADER="t_faid";
	public static final String GENERIC_HEADER = "t";
	public static final String SET_EXPIRATION ="SetTokenExpiration";

}
