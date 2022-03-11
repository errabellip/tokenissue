package com.errabelli.api.security.logging;

import java.util.ArrayList;
import java.util.List;

public class ReplacePatterns {

    private List<ReplacePattern> patterns = new ArrayList<ReplacePattern>();

    public ReplacePatterns() {

    }

    public void addReplacePattern(ReplacePattern replacePattern) {
        patterns.add(replacePattern);
    }

    public List<ReplacePattern> getPatterns() {
        return patterns;
    }
}
