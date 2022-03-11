package com.errabelli.api.security.logging;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

import ch.qos.logback.classic.PatternLayout;
import ch.qos.logback.classic.spi.ILoggingEvent;

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
@Component
public class CustomDigitalLayout extends PatternLayout {
    private static final String ENCODE_SUBSTITUTION_PREFIX = "ENC-SUB-";

    private static final String CRLF_REGEX_PATTERN = "\\r\\n([0-9]{4}-[0-9]{2}-[0-9]{2})";
    private static final String CRLF_REPLACE_STRING = ENCODE_SUBSTITUTION_PREFIX + "CRLF-$1";
    private static final Pattern COMPILED_CRLF_REGEX_PATTERN = java.util.regex.Pattern.compile(CRLF_REGEX_PATTERN);

    private static final String ACCOUNT_NUM_LIKE_REGEX_PATTERN = "([0-9]{10})";
    private static final String ACCOUNT_NUM_LIKE_REPLACE_STRING = ENCODE_SUBSTITUTION_PREFIX + "NUM-***";
    private static final Pattern COMPILED_ACCOUNT_NUM_LIKE_REGEX_PATTERN = java.util.regex.Pattern
            .compile(ACCOUNT_NUM_LIKE_REGEX_PATTERN);

    private static final String NON_PRINTABLE_CHARACTER_REGEX_PATTERN = "([^\\n\\r\\t\\p{Print}])";
    private static final String NON_PRINTABLE_CHARACTER_REPLACE_STRING = ENCODE_SUBSTITUTION_PREFIX + "NONP-*";
    private static final Pattern COMPILED_NON_PRINTABLE_CHARACTER_REGEX_PATTERN = java.util.regex.Pattern
            .compile(NON_PRINTABLE_CHARACTER_REGEX_PATTERN);

    private static final List<Pattern> COMPILED_MASK_PATTERNS = new ArrayList<Pattern>();
    private static final Map<Pattern, String> COMPILED_REPLACE_PATTERNS = new HashMap<Pattern, String>();

    public void setMaskPatterns(MaskPatterns maskPatterns) {
        if (maskPatterns != null && !maskPatterns.getPatterns().isEmpty()) {
            for (String pattern : maskPatterns.getPatterns()) {
                COMPILED_MASK_PATTERNS.add(java.util.regex.Pattern.compile(pattern));
            }
        }
    }

    public void setReplacePatterns(ReplacePatterns replacePatterns) {
        if (replacePatterns != null && !replacePatterns.getPatterns().isEmpty()) {
            for (ReplacePattern pattern : replacePatterns.getPatterns()) {
                COMPILED_REPLACE_PATTERNS.put(java.util.regex.Pattern.compile(pattern.getMatch()),
                        pattern.getReplaceWith());
            }
        }
    }

    @Override
    public String doLayout(ILoggingEvent event) {
        String layoutString = super.doLayout(event);
        String badCrlfSubstitutedLayoutString = COMPILED_CRLF_REGEX_PATTERN.matcher(layoutString)
                .replaceAll(CRLF_REPLACE_STRING);
        String accountLikeSubstitutedLayoutString = COMPILED_ACCOUNT_NUM_LIKE_REGEX_PATTERN
                .matcher(badCrlfSubstitutedLayoutString).replaceAll(ACCOUNT_NUM_LIKE_REPLACE_STRING);
        String nonPrintableSubstitutedLayoutString = COMPILED_NON_PRINTABLE_CHARACTER_REGEX_PATTERN
                .matcher(accountLikeSubstitutedLayoutString).replaceAll(NON_PRINTABLE_CHARACTER_REPLACE_STRING);
        String maskedLayoutString = nonPrintableSubstitutedLayoutString + "";
        for (Pattern pattern : COMPILED_MASK_PATTERNS) {
            maskedLayoutString = pattern.matcher(maskedLayoutString).replaceAll("******");
        }
        String replaceLayoutString = maskedLayoutString + "";

        for (Pattern pattern : COMPILED_REPLACE_PATTERNS.keySet()) {
            replaceLayoutString = pattern.matcher(replaceLayoutString)
                    .replaceAll(COMPILED_REPLACE_PATTERNS.get(pattern));
        }
        return replaceLayoutString;
    }

}