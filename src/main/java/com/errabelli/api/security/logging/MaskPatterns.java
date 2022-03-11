package com.errabelli.api.security.logging;

import java.util.ArrayList;
import java.util.List;

/**
 * SPLUNK's end of log event interpretation is based on
 * LINE_BREAKER=([\n\r]+)\d{4}-\d{2}-\d{2} \d{2}\:\d{2}\:\d{2}
 * 
 * This class will substitute a) Artificially injected Splunk log event
 * separator (pattern above) with ENC-SUB-CRLF b) 10 contiguous numbers (account
 * number) with one ENC-SUB-ACCT-*** c) Each non printable characters with
 * ENC_SUB-NONP-*
 * 
 * 
 * @author Kingsly Theodar Rajasekar
 *
 */

public class MaskPatterns {

    private List<String> patterns = new ArrayList<String>();

    public MaskPatterns() {

    }

    public void addPattern(String pattern) {
        patterns.add(pattern);
    }

    public List<String> getPatterns() {
        return patterns;
    }
}
