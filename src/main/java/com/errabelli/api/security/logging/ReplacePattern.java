package com.errabelli.api.security.logging;

public class ReplacePattern {

    private String match;
    private String replaceWith;

    public ReplacePattern() {

    }

    public String getMatch() {
        return match;
    }

    public void setMatch(String match) {
        this.match = match;
    }

    public String getReplaceWith() {
        return replaceWith;
    }

    public void setReplaceWith(String replaceWith) {
        this.replaceWith = replaceWith;
    }
}